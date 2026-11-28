//! The interactive terminal dashboard (ratatui).
//!
//! The capture loop runs on another thread and fills the shared [`Model`];
//! this draws a snapshot of it a few times a second and handles the keyboard.
//! Tabs: Overview, Live, Cells, Captures, Log. It only reads — quitting here
//! asks the capture loop to stop, it does not touch the radio directly.

use crate::model::{FeedLine, Level, Model, Phase, Snapshot};
use crate::{banner_plain, request_rescan, request_stop, stopping};
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::Frame;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const TABS: [&str; 5] = ["Overview", "Live", "Cells", "Captures", "Log"];

/// Redirects this process's stderr into the dashboard log for as long as it is
/// held, so lines the capture loop and its helpers print do not corrupt the
/// terminal. Restores the original stderr when dropped.
pub struct StderrGuard {
    saved: i32,
    write_fd: i32,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Drop for StderrGuard {
    fn drop(&mut self) {
        // SAFETY: these are our own file descriptors; dup2/close on them is
        // valid and restores stderr to what it was before.
        unsafe {
            libc::dup2(self.saved, libc::STDERR_FILENO);
            libc::close(self.saved);
            libc::close(self.write_fd);
        }
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

/// Send everything written to stderr to the model's log instead. The reader
/// thread ends when the guard is dropped and the write end is closed.
pub fn capture_stderr(model: Arc<Model>) -> StderrGuard {
    use std::io::{BufRead, BufReader};
    use std::os::fd::FromRawFd;

    let mut fds = [0i32; 2];
    // SAFETY: pipe() fills the two-element array; failure leaves stderr as is.
    let (read_fd, write_fd, saved) = unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            // Could not set up the pipe: leave stderr alone.
            return StderrGuard {
                saved: -1,
                write_fd: -1,
                reader: None,
            };
        }
        let saved = libc::dup(libc::STDERR_FILENO);
        libc::dup2(fds[1], libc::STDERR_FILENO);
        (fds[0], fds[1], saved)
    };
    let reader = std::thread::spawn(move || {
        // SAFETY: read_fd is a valid fd this thread now owns.
        let file = unsafe { std::fs::File::from_raw_fd(read_fd) };
        let mut lines = BufReader::new(file);
        let mut line = String::new();
        loop {
            line.clear();
            match lines.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let t = line.trim_end();
                    let (level, text) = if let Some(s) = t.strip_prefix("warning: ") {
                        (Level::Warn, s)
                    } else if let Some(s) = t.strip_prefix("info: ") {
                        (Level::Info, s)
                    } else {
                        (Level::Info, t)
                    };
                    if !text.is_empty() {
                        model.log(level, text);
                    }
                }
            }
        }
    });
    StderrGuard {
        saved,
        write_fd,
        reader: Some(reader),
    }
}

/// A capture file on disk, for the Captures tab.
struct FileRow {
    name: String,
    bytes: u64,
    modified: Option<SystemTime>,
}

fn tone_colour(tone: crate::live::Tone) -> Color {
    use crate::live::Tone::*;
    match tone {
        SystemInfo => Color::Cyan,
        Assignment => Color::Gray,
        Paging => Color::Yellow,
        Alert => Color::LightRed,
        Signalling => Color::LightBlue,
        Security => Color::LightMagenta,
        Sms => Color::LightGreen,
        Call => Color::LightCyan,
    }
}

fn phase_colour(phase: Phase) -> Color {
    match phase {
        Phase::Capturing => Color::Green,
        Phase::Scanning | Phase::Starting => Color::Yellow,
        Phase::Stalled => Color::LightRed,
        Phase::Stopping => Color::Gray,
    }
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn human_dur(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// List this tool's capture files in a directory, newest first.
fn capture_files(dir: &str) -> (Vec<FileRow>, u64) {
    let mut rows: Vec<FileRow> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !(name.starts_with("cellcap-gsm-") && name.ends_with(".pcapng")) {
                continue;
            }
            let meta = e.metadata().ok();
            rows.push(FileRow {
                name,
                bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                modified: meta.and_then(|m| m.modified().ok()),
            });
        }
    }
    let total = rows.iter().map(|r| r.bytes).sum();
    rows.sort_by_key(|a| std::cmp::Reverse(a.modified));
    (rows, total)
}

/// Run the dashboard until the user quits or the capture loop finishes.
pub fn run(model: Arc<Model>, finished: Arc<AtomicBool>) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut tab = 0usize;
    let mut tick = 0usize;
    let result = (|| -> Result<()> {
        loop {
            let snap = model.snapshot();
            terminal.draw(|f| draw(f, &snap, tab, tick))?;
            tick = tick.wrapping_add(1);

            if finished.load(Ordering::Relaxed) || stopping() {
                break;
            }
            if event::poll(Duration::from_millis(125))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if ctrl => break,
                        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                            tab = (tab + 1) % TABS.len()
                        }
                        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                            tab = (tab + TABS.len() - 1) % TABS.len()
                        }
                        KeyCode::Char(c @ '1'..='5') => {
                            tab = (c as usize - '1' as usize).min(TABS.len() - 1)
                        }
                        KeyCode::Char('r') => request_rescan(),
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    })();
    ratatui::restore();
    // Leaving the dashboard means the operator wants to stop capturing.
    request_stop();
    result
}

/// Braille spinner frames, advanced once per draw to show the loop is live.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A human description of what the capture loop is doing, for the status bar.
fn status_text(phase: Phase, channel: &str) -> String {
    match phase {
        Phase::Starting => "Initialising".into(),
        Phase::Scanning => "Scanning for cells".into(),
        Phase::Capturing if channel.is_empty() => "Monitoring".into(),
        Phase::Capturing => format!("Monitoring {channel}"),
        Phase::Stalled => "Stalled — restarting decoder".into(),
        Phase::Stopping => "Stopping".into(),
    }
}

fn draw(f: &mut Frame, snap: &Snapshot, tab: usize, tick: usize) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Length(1), // tabs
            Constraint::Min(3),    // body
            Constraint::Length(1), // status
            Constraint::Length(1), // keys
        ])
        .split(f.area());

    let phase = snap.phase;
    let title = Line::from(vec![
        Span::styled(
            " cellcap ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {} ", phase.label()),
            Style::default()
                .fg(Color::Black)
                .bg(phase_colour(phase))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(snap.channel.clone(), Style::default().fg(Color::White)),
    ]);
    f.render_widget(Paragraph::new(title), rows[0]);

    let tabs = Tabs::new(TABS.iter().map(|t| Line::from(*t)).collect::<Vec<_>>())
        .select(tab)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(" ");
    f.render_widget(tabs, rows[1]);

    match tab {
        0 => overview(f, snap, rows[2]),
        1 => live(f, snap, rows[2]),
        2 => cells(f, snap, rows[2]),
        3 => captures(f, snap, rows[2]),
        _ => log(f, snap, rows[2]),
    }

    status_bar(f, snap, rows[3], tick);
    let keys = Line::from(vec![Span::styled(
        "  [Tab/←→] switch tab   [1-5] jump   [r] rescan   [q] quit",
        Style::default().fg(Color::DarkGray),
    )]);
    f.render_widget(Paragraph::new(keys), rows[4]);
}

fn status_bar(f: &mut Frame, snap: &Snapshot, area: Rect, tick: usize) {
    let c = &snap.counts;
    let out = snap.output.clone().unwrap_or_else(|| "not writing".into());
    // A still glyph once stopping, an animated braille spinner while working.
    let spin = if snap.phase == Phase::Stopping {
        "·"
    } else {
        SPINNER[tick % SPINNER.len()]
    };
    let text = Line::from(vec![
        Span::styled(
            format!("  {spin} "),
            Style::default()
                .fg(phase_colour(snap.phase))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            status_text(snap.phase, &snap.channel),
            Style::default()
                .fg(phase_colour(snap.phase))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   device ", Style::default().fg(Color::DarkGray)),
        Span::raw(snap.device.clone()),
        Span::styled("   up ", Style::default().fg(Color::DarkGray)),
        Span::raw(human_dur(snap.uptime)),
        Span::styled("   frames ", Style::default().fg(Color::DarkGray)),
        Span::styled(c.frames().to_string(), Style::default().fg(Color::White)),
        Span::styled("   written ", Style::default().fg(Color::DarkGray)),
        Span::styled(c.written.to_string(), Style::default().fg(Color::Green)),
        Span::styled("   → ", Style::default().fg(Color::DarkGray)),
        Span::raw(out),
    ]);
    f.render_widget(Paragraph::new(text), area);
}

fn overview(f: &mut Frame, snap: &Snapshot, area: Rect) {
    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);

    // Left: banner (if it fits) over the counters.
    let banner = banner_plain();
    let banner_lines: Vec<&str> = banner.lines().collect();
    let left = halves[0];
    let c = &snap.counts;
    let mut text: Vec<Line> = Vec::new();
    if left.height as usize > banner_lines.len() + 8 {
        for l in &banner_lines {
            text.push(Line::styled(
                (*l).to_string(),
                Style::default().fg(Color::Red),
            ));
        }
        text.push(Line::raw(""));
    }
    let stat = |name: &str, v: String, col: Color| {
        Line::from(vec![
            Span::styled(format!("  {name:<22}"), Style::default().fg(Color::Gray)),
            Span::styled(v, Style::default().fg(col).add_modifier(Modifier::BOLD)),
        ])
    };
    text.push(stat(
        "System Information",
        c.system_info.to_string(),
        Color::Cyan,
    ));
    text.push(stat("Paging", c.paging.to_string(), Color::Yellow));
    text.push(stat(
        "Immediate Assignment",
        c.assignments.to_string(),
        Color::White,
    ));
    text.push(stat("Other", c.other.to_string(), Color::DarkGray));
    text.push(stat(
        "Written to pcapng",
        c.written.to_string(),
        Color::Green,
    ));
    text.push(stat(
        "Dropped (paging)",
        c.dropped.to_string(),
        Color::DarkGray,
    ));
    text.push(stat(
        "Cells identified",
        snap.cells.len().to_string(),
        Color::LightMagenta,
    ));
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" Summary ")),
        left,
    );

    // Right: top cells and the capture directory total.
    let mut right_text: Vec<Line> = Vec::new();
    right_text.push(Line::styled(
        " Cells seen",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if snap.cells.is_empty() {
        right_text.push(Line::styled(
            "   (none yet)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    for cell in snap.cells.iter().take(6) {
        right_text.push(Line::from(vec![
            Span::styled(
                format!("   ARFCN {:<5}", cell.arfcn),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!(
                    "MCC {} MNC {} LAC {} CID {}",
                    cell.cell.mcc, cell.cell.mnc, cell.cell.lac, cell.cell.cid
                ),
                Style::default().fg(Color::LightMagenta),
            ),
            Span::styled(
                format!("  {} dBm", cell.signal_dbm),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    right_text.push(Line::raw(""));
    if let Some(dir) = &snap.output {
        let (files, total) = capture_files(dir);
        right_text.push(Line::from(vec![
            Span::styled(" Captures  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{} file(s), {}", files.len(), human_bytes(total)),
                Style::default().fg(Color::Green),
            ),
        ]));
        right_text.push(Line::styled(
            format!("   {dir}"),
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        right_text.push(Line::styled(
            " Not writing capture files (--no-write)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    f.render_widget(
        Paragraph::new(right_text)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Findings ")),
        halves[1],
    );
}

fn feed_line(l: &FeedLine) -> Line<'static> {
    Line::from(vec![
        Span::styled(l.time.clone(), Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(
            format!("ARFCN {:<4}", l.arfcn),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!(" {:>4} dBm  ", l.dbm),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{:<9}", crate::inspect::channel_name(l.chan)),
            Style::default().fg(Color::Rgb(120, 120, 140)),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<24}", l.label),
            Style::default().fg(tone_colour(l.tone)),
        ),
        Span::raw(" "),
        Span::raw(l.detail.clone()),
    ])
}

fn live(f: &mut Frame, snap: &Snapshot, area: Rect) {
    let title = format!(
        " Live  ({} shown, {} repeats hidden) ",
        snap.feed.len(),
        snap.hidden
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let h = inner.height as usize;
    let start = snap.feed.len().saturating_sub(h);
    let lines: Vec<Line> = snap.feed[start..].iter().map(feed_line).collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn cells(f: &mut Frame, snap: &Snapshot, area: Rect) {
    let header = Row::new([
        "ARFCN", "NETWORK", "MCC", "MNC", "LAC", "CID", "dBm", "frames",
    ])
    .style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row> = snap
        .cells
        .iter()
        .map(|c| {
            let net = crate::e212::short(&c.cell.mcc, &c.cell.mnc);
            Row::new([
                c.arfcn.to_string(),
                if net.is_empty() { "—".into() } else { net },
                c.cell.mcc.clone(),
                c.cell.mnc.clone(),
                c.cell.lac.to_string(),
                c.cell.cid.to_string(),
                c.signal_dbm.to_string(),
                c.frames.to_string(),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(7),
        Constraint::Length(22),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Cells  ({}) ", snap.cells.len())),
    );
    f.render_widget(table, area);
}

fn captures(f: &mut Frame, snap: &Snapshot, area: Rect) {
    let Some(dir) = &snap.output else {
        f.render_widget(
            Paragraph::new("Not writing capture files (--no-write).")
                .block(Block::default().borders(Borders::ALL).title(" Captures ")),
            area,
        );
        return;
    };
    let (files, total) = capture_files(dir);
    let header = Row::new(["file", "size", "modified"]).style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row> = files
        .iter()
        .map(|r| {
            let when = r
                .modified
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| {
                    use chrono::TimeZone;
                    chrono::Local
                        .timestamp_opt(d.as_secs() as i64, 0)
                        .single()
                        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            Row::new([r.name.clone(), human_bytes(r.bytes), when])
        })
        .collect();
    let widths = [
        Constraint::Percentage(50),
        Constraint::Length(12),
        Constraint::Length(21),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default().borders(Borders::ALL).title(format!(
            " Captures in {dir}  —  {} file(s), {} total ",
            files.len(),
            human_bytes(total)
        )),
    );
    f.render_widget(table, area);
}

fn log(f: &mut Frame, snap: &Snapshot, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Log ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let h = inner.height as usize;
    let start = snap.log.len().saturating_sub(h);
    let lines: Vec<Line> = snap.log[start..]
        .iter()
        .map(|l| {
            let col = match l.level {
                Level::Info => Color::Gray,
                Level::Warn => Color::LightRed,
            };
            Line::from(vec![
                Span::styled(l.time.clone(), Style::default().fg(Color::DarkGray)),
                Span::raw(" "),
                Span::styled(l.text.clone(), Style::default().fg(col)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_describes_each_phase() {
        assert_eq!(status_text(Phase::Starting, ""), "Initialising");
        assert_eq!(status_text(Phase::Scanning, ""), "Scanning for cells");
        assert_eq!(status_text(Phase::Stopping, ""), "Stopping");
        assert_eq!(
            status_text(Phase::Stalled, ""),
            "Stalled — restarting decoder"
        );
        // Capturing names the channel it is monitoring when there is one.
        assert_eq!(status_text(Phase::Capturing, ""), "Monitoring");
        assert_eq!(
            status_text(Phase::Capturing, "937.2 MHz (ARFCN 11)"),
            "Monitoring 937.2 MHz (ARFCN 11)"
        );
    }

    #[test]
    fn spinner_cycles_through_all_frames() {
        // Every tick maps to a frame, and it wraps without panicking.
        let frames: std::collections::HashSet<&str> = (0..SPINNER.len())
            .map(|t| SPINNER[t % SPINNER.len()])
            .collect();
        assert_eq!(frames.len(), SPINNER.len());
        assert_eq!(SPINNER[0], SPINNER[SPINNER.len() % SPINNER.len()]);
    }
}
