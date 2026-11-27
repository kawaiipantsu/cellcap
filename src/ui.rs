//! The interactive control panel: `cellcap` with no arguments (or `cellcap ui`).
//!
//! A home menu lists every cellcap mode; choosing one opens a form of its
//! options; running it streams the output into a scrollable pane — all without
//! leaving the UI. Rather than re-enter each command in-process (and nest one
//! TUI inside another for the live dashboard), the panel runs the *same cellcap
//! binary* as a child, one subcommand at a time, and shows its output live.
//! Every feature is therefore reachable from here with nothing special to wire
//! up per command.

use anyhow::{Context, Result};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ACCENT: Color = Color::Rgb(255, 70, 85); // THUGSred
const DIM: Color = Color::Rgb(150, 150, 150);
const GOOD: Color = Color::Rgb(120, 220, 130);

/// How a field turns into command-line arguments.
#[derive(Clone)]
enum Kind {
    /// Free text. A flag plus the value, or just the value when `flag` is empty
    /// (a positional argument). Nothing is added when the text is empty.
    Text,
    /// A boolean. The flag is added when on, nothing when off.
    Flag,
    /// One of a fixed set, cycled with ←/→. The flag plus the chosen value.
    Choice(Vec<&'static str>),
}

#[derive(Clone)]
struct Field {
    flag: &'static str,
    label: &'static str,
    kind: Kind,
    value: String,
    help: &'static str,
}

impl Field {
    fn text(flag: &'static str, label: &'static str, default: &str, help: &'static str) -> Self {
        Field { flag, label, kind: Kind::Text, value: default.to_string(), help }
    }
    fn flag(flag: &'static str, label: &'static str, on: bool, help: &'static str) -> Self {
        Field { flag, label, kind: Kind::Flag, value: if on { "on" } else { "off" }.into(), help }
    }
    fn choice(flag: &'static str, label: &'static str, opts: Vec<&'static str>, help: &'static str) -> Self {
        let value = opts[0].to_string();
        Field { flag, label, kind: Kind::Choice(opts), value, help }
    }

    /// The value shown in the form.
    fn shown(&self) -> String {
        match &self.kind {
            Kind::Flag => if self.value == "on" { "● on".into() } else { "○ off".into() },
            _ => if self.value.is_empty() { "—".into() } else { self.value.clone() },
        }
    }

    /// Append this field's contribution to an argument list.
    fn push_args(&self, out: &mut Vec<String>) {
        match &self.kind {
            Kind::Flag => {
                if self.value == "on" && !self.flag.is_empty() {
                    out.push(self.flag.into());
                }
            }
            _ => {
                if self.value.trim().is_empty() {
                    return;
                }
                if self.flag.is_empty() {
                    out.push(self.value.trim().into());
                } else {
                    out.push(self.flag.into());
                    out.push(self.value.trim().into());
                }
            }
        }
    }
}

struct Action {
    cmd: &'static str,
    title: &'static str,
    blurb: &'static str,
    /// Arguments always added, hidden from the form (e.g. `--stream`).
    baked: Vec<&'static str>,
    fields: Vec<Field>,
    /// Shown in the form as a reminder (e.g. that root is needed).
    note: &'static str,
}

fn actions() -> Vec<Action> {
    let dev = |d| Field::text("--device", "SDR device", d, "gr-osmosdr args: rtl=0, hackrf=0, uhd");
    let modem = Field::text("", "Modem device", "/dev/ttyUSB0", "serial port of the GSM modem (positional)");
    let baud = Field::text("--baud", "Baud", "115200", "serial baud rate");
    vec![
        Action {
            cmd: "check", title: "Check", blurb: "Preflight: required tools and an SDR, with ✓/✗.",
            baked: vec![], fields: vec![], note: "",
        },
        Action {
            cmd: "scan", title: "Scan", blurb: "Find GSM cells in a band and list them.",
            baked: vec![], note: "",
            fields: vec![
                dev("rtl=0"),
                Field::choice("--band", "Band", vec!["GSM900", "DCS1800", "GSM850"], "band to sweep"),
                Field::text("--scan-top", "Top channels", "8", "probe this many strong channels"),
                Field::text("--probe-seconds", "Probe seconds", "15", "listen time per channel"),
            ],
        },
        Action {
            cmd: "run", title: "Capture (GSM)", blurb: "Capture broadcast/control channels to pcapng.",
            baked: vec!["--stream"], note: "",
            fields: vec![
                dev("rtl=0"),
                Field::text("--arfcn", "ARFCN", "", "channel number, e.g. 11 (or set frequency)"),
                Field::text("--freq", "Frequency", "", "e.g. 937.2M (instead of ARFCN)"),
                Field::text("--plmn", "PLMN filter", "", "after a scan, only this MCCMNC, e.g. 23801"),
                Field::text("--dwell", "Dwell seconds", "120", "time per channel when cycling"),
                Field::text("--output-dir", "Output dir", "/var/lib/cellcap/captures", "where pcapng files go"),
                Field::text("--gsmtap-udp", "Mirror to UDP", "", "live remote Wireshark, e.g. 172.22.22.20:4729"),
                Field::flag("--no-write", "Watch only (don't save)", false, "stream without writing files"),
                Field::flag("--drop-paging", "Drop paging", false, "leave others' paging identities out"),
            ],
        },
        Action {
            cmd: "lte", title: "Capture (LTE 4G)", blurb: "Downlink → MAC-LTE pcap (drives LTESniffer).",
            baked: vec!["--verbose"], note: "needs root (SDR + real-time) and a B210-class SDR",
            fields: vec![
                Field::text("--earfcn", "EARFCN", "", "downlink EARFCN (FDD bands 1–66)"),
                Field::text("--freq", "Frequency", "", "e.g. 1842.5M (instead of EARFCN)"),
                Field::choice("--antennas", "Antennas", vec!["2", "1"], "2 = 2×2 MIMO, 1 = single stream"),
                Field::text("--threads", "Threads", "4", "decoder worker threads"),
                Field::text("--gain", "Gain (dB)", "", "fixed RX gain, blank = AGC"),
                Field::text("--rf-args", "RF args", "num_recv_frames=512", "UHD args for LTESniffer -a"),
                Field::text("--cell-id", "Cell id", "", "lock a PCI (needs PRB) instead of searching"),
                Field::text("--prb", "PRB", "", "cell bandwidth in resource blocks"),
                Field::text("--output-dir", "Output dir", "/var/lib/cellcap/captures", "where the pcap goes"),
            ],
        },
        Action {
            cmd: "decode", title: "Decode channel", blurb: "SDCCH/TCH into pcapng, with optional A5 decrypt.",
            baked: vec![], note: "",
            fields: vec![
                dev("rtl=0"),
                Field::text("--arfcn", "ARFCN", "11", "channel number"),
                Field::text("--freq", "Frequency", "", "instead of ARFCN"),
                Field::choice("--mode", "Mode", vec!["sdcch8", "bcch-sdcch4", "bcch", "tchf", "tchh"], "channel to decode"),
                Field::text("--timeslot", "Timeslot", "1", "0–7"),
                Field::text("--subslot", "Subslot", "", "for bcch-sdcch4 / sdcch8"),
                Field::text("--cipher-a5", "A5 version", "", "1, 2 or 3 (with the Kc below)"),
                Field::text("--cipher-kc", "Session key Kc", "", "hex, e.g. 1234567890ABCDEF"),
                Field::text("--cfile", "Input cfile", "", "decode this recording instead of the SDR"),
                Field::text("--output-dir", "Output dir", "/var/lib/cellcap/captures", "where the pcapng goes"),
            ],
        },
        Action {
            cmd: "inspect", title: "Inspect capture", blurb: "Summarise a pcapng file (no SDR needed).",
            baked: vec![], note: "",
            fields: vec![Field::text("", "Capture file", "", "path to a .pcapng (positional)")],
        },
        Action {
            cmd: "sim-info", title: "SIM info", blurb: "IMSI, Kc, GPRS Kc, TMSI/LAI from the SIM.",
            baked: vec![], note: "stop any program holding the modem first",
            fields: vec![modem.clone(), baud.clone()],
        },
        Action {
            cmd: "extract-kc", title: "Extract Kc", blurb: "Read the A5 session key Kc from the SIM.",
            baked: vec![], note: "stop any program holding the modem first",
            fields: vec![modem.clone(), baud.clone()],
        },
        Action {
            cmd: "audit-sim", title: "Audit SIM", blurb: "Toolkit/OTA attack surface (Simjacker/WIB class).",
            baked: vec![], note: "stop any program holding the modem first",
            fields: vec![modem, baud],
        },
        Action {
            cmd: "disclaimer", title: "Disclaimer", blurb: "Legal/ethical notice — read before capturing.",
            baked: vec![], fields: vec![], note: "",
        },
    ]
}

/// A running child and the lines it has produced.
struct RunState {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    cmdline: String,
    started: Instant,
    exit: Option<String>,
}

impl RunState {
    /// Send SIGINT so the child (our own binary) stops gracefully.
    fn stop(&self) {
        // SAFETY: the pid is a child we spawned and have not reaped.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGINT);
        }
    }
}

enum Screen {
    Home,
    Form,
    Running,
}

struct App {
    actions: Vec<Action>,
    screen: Screen,
    menu: ListState,
    field: usize,
    run: Option<RunState>,
    /// Lines from the top to hide; None means follow the tail.
    scroll: Option<usize>,
}

pub fn run() -> Result<()> {
    let mut app = App {
        actions: actions(),
        screen: Screen::Home,
        menu: ListState::default().with_selected(Some(0)),
        field: 0,
        run: None,
        scroll: None,
    };

    let mut terminal = ratatui::init();
    let res = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    // Make sure we never leave a child capturing the SDR behind us.
    if let Some(r) = &app.run {
        r.stop();
    }
    res
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        // Reap a finished child so the output pane can show its exit status.
        if let Some(r) = app.run.as_mut() {
            if r.exit.is_none() {
                if let Ok(Some(status)) = r.child.try_wait() {
                    r.exit = Some(match status.code() {
                        Some(0) => "finished".into(),
                        Some(c) => format!("exited with status {c}"),
                        None => "stopped".into(),
                    });
                }
            }
        }

        terminal.draw(|f| draw(f, app))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(k) = event::read()? else { continue };
        if k.kind != event::KeyEventKind::Press {
            continue;
        }
        // Ctrl-C always quits.
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(());
        }
        match app.screen {
            Screen::Home => {
                if home_keys(app, k.code) {
                    return Ok(());
                }
            }
            Screen::Form => form_keys(app, k.code),
            Screen::Running => running_keys(app, k.code),
        }
    }
}

/// Returns true to quit the app.
fn home_keys(app: &mut App, code: KeyCode) -> bool {
    let n = app.actions.len();
    let sel = app.menu.selected().unwrap_or(0);
    match code {
        KeyCode::Char('q') => return true,
        KeyCode::Up | KeyCode::Char('k') => app.menu.select(Some((sel + n - 1) % n)),
        KeyCode::Down | KeyCode::Char('j') => app.menu.select(Some((sel + 1) % n)),
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            app.field = 0;
            app.screen = if app.actions[sel].fields.is_empty() {
                start_run(app);
                Screen::Running
            } else {
                Screen::Form
            };
        }
        _ => {}
    }
    false
}

fn form_keys(app: &mut App, code: KeyCode) {
    let sel = app.menu.selected().unwrap_or(0);
    let nfields = app.actions[sel].fields.len();
    match code {
        KeyCode::Esc => app.screen = Screen::Home,
        KeyCode::Enter => {
            start_run(app);
            app.screen = Screen::Running;
        }
        KeyCode::Up => app.field = (app.field + nfields - 1) % nfields,
        KeyCode::Down | KeyCode::Tab => app.field = (app.field + 1) % nfields,
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') => {
            adjust_field(&mut app.actions[sel].fields[app.field], code)
        }
        KeyCode::Backspace => {
            let f = &mut app.actions[sel].fields[app.field];
            if matches!(f.kind, Kind::Text) {
                f.value.pop();
            }
        }
        KeyCode::Char(c) => {
            let f = &mut app.actions[sel].fields[app.field];
            if matches!(f.kind, Kind::Text) {
                f.value.push(c);
            }
        }
        _ => {}
    }
}

/// Toggle a flag or cycle a choice. Left and ' ' go one way, Right the other.
fn adjust_field(f: &mut Field, code: KeyCode) {
    match &f.kind {
        Kind::Flag => f.value = if f.value == "on" { "off".into() } else { "on".into() },
        Kind::Choice(opts) => {
            let i = opts.iter().position(|o| *o == f.value).unwrap_or(0);
            let next = if matches!(code, KeyCode::Left) {
                (i + opts.len() - 1) % opts.len()
            } else {
                (i + 1) % opts.len()
            };
            f.value = opts[next].to_string();
        }
        Kind::Text => {}
    }
}

fn running_keys(app: &mut App, code: KeyCode) {
    let finished = app.run.as_ref().map(|r| r.exit.is_some()).unwrap_or(true);
    match code {
        KeyCode::Char('s') => {
            if let Some(r) = &app.run {
                r.stop();
            }
        }
        KeyCode::Esc | KeyCode::Char('b') => {
            if let Some(r) = &app.run {
                if !finished {
                    r.stop();
                }
            }
            app.run = None;
            app.scroll = None;
            app.screen = Screen::Home;
        }
        KeyCode::Up | KeyCode::Char('k') => scroll_by(app, -1),
        KeyCode::Down | KeyCode::Char('j') => scroll_by(app, 1),
        KeyCode::PageUp => scroll_by(app, -10),
        KeyCode::PageDown => scroll_by(app, 10),
        KeyCode::End | KeyCode::Char('g') => app.scroll = None, // follow tail again
        _ => {}
    }
}

fn scroll_by(app: &mut App, delta: isize) {
    let total = app
        .run
        .as_ref()
        .map(|r| r.lines.lock().map(|l| l.len()).unwrap_or(0))
        .unwrap_or(0);
    let cur = app.scroll.unwrap_or(total.saturating_sub(1)) as isize;
    let next = (cur + delta).clamp(0, total.saturating_sub(1) as isize) as usize;
    app.scroll = Some(next);
}

/// Build the command line for the selected action and spawn it.
fn start_run(app: &mut App) {
    let sel = app.menu.selected().unwrap_or(0);
    let action = &app.actions[sel];
    let mut args: Vec<String> = vec![action.cmd.into()];
    for b in &action.baked {
        args.push((*b).into());
    }
    for f in &action.fields {
        f.push_args(&mut args);
    }

    let exe = std::env::current_exe().unwrap_or_else(|_| "cellcap".into());
    let cmdline = format!("cellcap {}", args.join(" "));
    let lines = Arc::new(Mutex::new(vec![format!("$ {cmdline}"), String::new()]));

    let spawned = Command::new(&exe)
        .args(&args)
        .env("NO_COLOR", "1") // plain text in the pane
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", exe.display()));

    match spawned {
        Ok(mut child) => {
            pump(child.stdout.take(), lines.clone());
            pump(child.stderr.take(), lines.clone());
            app.scroll = None;
            app.run = Some(RunState {
                child,
                lines,
                cmdline,
                started: Instant::now(),
                exit: None,
            });
        }
        Err(e) => {
            if let Ok(mut l) = lines.lock() {
                l.push(format!("error: {e:#}"));
            }
            app.run = Some(RunState {
                child: dummy_child(),
                lines,
                cmdline,
                started: Instant::now(),
                exit: Some("failed to start".into()),
            });
        }
    }
}

/// Read a child stream line by line into the shared buffer, on its own thread.
fn pump<R: std::io::Read + Send + 'static>(stream: Option<R>, lines: Arc<Mutex<Vec<String>>>) {
    let Some(stream) = stream else { return };
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(std::result::Result::ok) {
            if let Ok(mut l) = lines.lock() {
                l.push(line);
            }
        }
    });
}

/// A placeholder child for the spawn-failed case (never waited on meaningfully).
fn dummy_child() -> Child {
    Command::new("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn `true`")
}

// ---- drawing ---------------------------------------------------------------

fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    title_bar(f, chunks[0]);
    match app.screen {
        Screen::Home => draw_home(f, app, chunks[1]),
        Screen::Form => draw_form(f, app, chunks[1]),
        Screen::Running => draw_running(f, app, chunks[1]),
    }
    footer(f, app, chunks[2]);
}

fn title_bar(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled("  cellcap ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("control panel", Style::default().fg(Color::White)),
        Span::styled("  ·  passive cellular capture for Wireshark", Style::default().fg(DIM)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_home(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(0)])
        .split(area);

    let items: Vec<ListItem> = app
        .actions
        .iter()
        .map(|a| ListItem::new(a.title))
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" modes "))
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    let mut state = app.menu.clone();
    f.render_stateful_widget(list, cols[0], &mut state);

    // Detail panel for the highlighted mode.
    let sel = app.menu.selected().unwrap_or(0);
    let a = &app.actions[sel];
    let mut lines = vec![
        Line::from(Span::styled(a.title, Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled(a.blurb, Style::default().fg(DIM))),
        Line::from(""),
        Line::from(vec![
            Span::styled("command  ", Style::default().fg(DIM)),
            Span::styled(format!("cellcap {}", a.cmd), Style::default().fg(GOOD)),
        ]),
        Line::from(vec![
            Span::styled("options  ", Style::default().fg(DIM)),
            Span::raw(if a.fields.is_empty() {
                "none — runs immediately".to_string()
            } else {
                format!("{} field(s) to set", a.fields.len())
            }),
        ]),
    ];
    if !a.note.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("note: {}", a.note), Style::default().fg(Color::Yellow))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Enter to configure and run", Style::default().fg(DIM))));
    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" about "))
        .wrap(Wrap { trim: true });
    f.render_widget(detail, cols[1]);
}

fn draw_form(f: &mut Frame, app: &App, area: Rect) {
    let sel = app.menu.selected().unwrap_or(0);
    let a = &app.actions[sel];
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let mut items: Vec<ListItem> = Vec::new();
    for (i, field) in a.fields.iter().enumerate() {
        let selected = i == app.field;
        let marker = if selected { "▶ " } else { "  " };
        let label_style = if selected {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let val_style = match field.kind {
            Kind::Flag if field.value == "on" => Style::default().fg(GOOD),
            _ => Style::default().fg(Color::Cyan),
        };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(marker, Style::default().fg(ACCENT)),
            Span::styled(format!("{:<26}", field.label), label_style),
            Span::styled(field.shown(), val_style),
        ])));
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} — set options ", a.title)),
    );
    f.render_widget(list, rows[0]);

    // Help for the current field.
    let help = a.fields.get(app.field).map(|x| x.help).unwrap_or("");
    let hint = Paragraph::new(Line::from(Span::styled(help, Style::default().fg(DIM))))
        .block(Block::default().borders(Borders::ALL).title(" this option "));
    f.render_widget(hint, rows[1]);
}

fn draw_running(f: &mut Frame, app: &App, area: Rect) {
    let Some(run) = &app.run else { return };
    let guard = run.lines.lock();
    let lines = guard.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);

    let inner_h = area.height.saturating_sub(2) as usize;
    let total = lines.len();
    let start = match app.scroll {
        None => total.saturating_sub(inner_h), // follow the tail
        Some(s) => s.min(total.saturating_sub(1)).saturating_sub(inner_h / 2).min(total.saturating_sub(inner_h.max(1))),
    };
    let shown: Vec<Line> = lines[start.min(total)..]
        .iter()
        .take(inner_h)
        .map(|l| Line::from(Span::raw(l.clone())))
        .collect();

    let status = match &run.exit {
        None => format!("running ({}s)  ·  s stop", run.started.elapsed().as_secs()),
        Some(e) => format!("{e}  ·  Esc back"),
    };
    let title = format!(" {}  [{}] ", run.cmdline, status);
    let para = Paragraph::new(shown)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });
    f.render_widget(Clear, area);
    f.render_widget(para, area);
}

fn footer(f: &mut Frame, app: &App, area: Rect) {
    let keys = match app.screen {
        Screen::Home => "↑↓ move   Enter configure   q quit",
        Screen::Form => "↑↓ field   ←→/Space change   type to edit   Enter run   Esc back",
        Screen::Running => "↑↓ scroll   End follow   s stop   Esc back   Ctrl-C quit",
    };
    let p = Paragraph::new(Line::from(Span::styled(keys, Style::default().fg(DIM))))
        .alignment(Alignment::Left);
    f.render_widget(p, area);
}
