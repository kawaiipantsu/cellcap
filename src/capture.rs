//! The capture loop: keep a decoder running on the chosen channel(s),
//! receive its GSMTAP frames and write them to the capture files.
//!
//! The loop reports what it does through a [`Reporter`], which is one of three
//! things: plain stderr lines for a headless run, the readable stdout stream
//! view, or the shared [`Model`] the interactive TUI draws from.

use crate::freq::{self, Band};
use crate::gsmtap::{self, Cell, Kind};
use crate::live::Live;
use crate::model::{Counts, Level, Model, Phase};
use crate::pcapng::{self, Writer};
use crate::radio::{self, Radio};
use crate::scan;
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Options {
    /// Channels to capture. Empty means: scan and pick.
    pub targets: Vec<u64>,
    pub bands: Vec<Band>,
    /// How many of the cells a scan finds to capture.
    pub cells: usize,
    /// Only pick cells of this network (MCC followed by MNC).
    pub plmn: Option<String>,
    pub scan_top: usize,
    pub probe_seconds: u64,
    /// Time on each channel when there are several.
    pub dwell: Duration,
    /// Restart the decoder when nothing arrives for this long.
    pub stall: Duration,
    pub drop_paging: bool,
}

/// Where the capture loop sends what it sees.
pub enum Reporter {
    /// Plain lines on stderr (the service and non-interactive runs).
    Headless,
    /// The readable one-line-per-message view on stdout.
    Stream(Live),
    /// The shared model the interactive TUI draws.
    Tui(Arc<Model>),
}

impl Reporter {
    fn info(&mut self, msg: &str) {
        match self {
            Reporter::Headless | Reporter::Stream(_) => eprintln!("info: {msg}"),
            Reporter::Tui(m) => m.log(Level::Info, msg),
        }
    }

    fn warn(&mut self, msg: &str) {
        match self {
            Reporter::Headless | Reporter::Stream(_) => eprintln!("warning: {msg}"),
            Reporter::Tui(m) => m.log(Level::Warn, msg),
        }
    }

    fn phase(&mut self, phase: Phase) {
        if let Reporter::Tui(m) = self {
            m.set_phase(phase);
        }
    }

    /// The decoder has moved to a channel.
    fn channel(&mut self, label: &str) {
        match self {
            Reporter::Headless => eprintln!("info: capturing {label}"),
            Reporter::Stream(l) => l.heading(&format!("Listening on {label}")),
            Reporter::Tui(m) => {
                m.set_channel(label);
                m.log(Level::Info, &format!("capturing {label}"));
            }
        }
    }

    /// A cell identified itself for the first time this run.
    fn cell(&mut self, arfcn: u16, cell: &Cell, dbm: i8) {
        let text = format!(
            "cell on ARFCN {arfcn}: MCC {} MNC {} LAC {} CID {} ({dbm} dBm)",
            cell.mcc, cell.mnc, cell.lac, cell.cid
        );
        match self {
            // The stream view shows the cell in its message lines already.
            Reporter::Headless => eprintln!("info: {text}"),
            Reporter::Stream(_) => {}
            Reporter::Tui(m) => m.log(Level::Info, &text),
        }
    }

    fn frame(&mut self, header: &gsmtap::Header, frame: &[u8]) {
        match self {
            Reporter::Headless => {}
            Reporter::Stream(l) => l.frame(header, frame),
            Reporter::Tui(m) => m.frame(header, frame),
        }
    }

    /// Push the written/dropped totals to the model (TUI only).
    fn totals(&mut self, written: u64, dropped: u64) {
        if let Reporter::Tui(m) = self {
            m.set_written(written, dropped);
        }
    }

    /// A periodic summary of the counters.
    fn summary(&mut self, c: &Counts) {
        let text = format!(
            "{} frames ({} system information, {} paging, {} assignments, {} other), {} written, {} dropped",
            c.frames(), c.system_info, c.paging, c.assignments, c.other, c.written, c.dropped
        );
        match self {
            Reporter::Headless => eprintln!("info: {text}"),
            Reporter::Stream(l) => l.summary(&text),
            Reporter::Tui(m) => m.set_written(c.written, c.dropped),
        }
    }
}

/// Sleep that ends early on shutdown.
fn pause(d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end && !crate::stopping() {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Scan until at least one cell is found, then return the channels to use.
fn pick(radio: &Radio, socket: &UdpSocket, rep: &mut Reporter, o: &Options) -> Result<Vec<u64>> {
    let mut wait = Duration::from_secs(30);
    loop {
        rep.phase(Phase::Scanning);
        let found = scan::scan(radio, socket, &o.bands, o.scan_top, o.probe_seconds)?;
        if crate::stopping() {
            return Ok(Vec::new());
        }
        let picks: Vec<u64> = found
            .iter()
            .filter(|f| f.frames > 0)
            .filter(|f| match (&o.plmn, &f.cell) {
                (Some(want), Some(cell)) => format!("{}{}", cell.mcc, cell.mnc) == *want,
                (Some(_), None) => false,
                (None, _) => true,
            })
            .take(o.cells.max(1))
            .map(|f| f.candidate.hz)
            .collect();
        if !picks.is_empty() {
            return Ok(picks);
        }
        rep.warn(&format!(
            "no usable cell found{}; scanning again in {} s",
            o.plmn
                .as_ref()
                .map(|p| format!(" for network {p}"))
                .unwrap_or_default(),
            wait.as_secs()
        ));
        pause(wait);
        wait = (wait * 2).min(Duration::from_secs(600));
    }
}

/// `writer` is `None` when nothing is to be saved.
pub fn run(
    radio: &Radio,
    socket: &UdpSocket,
    mut writer: Option<&mut Writer>,
    mut rep: Reporter,
    o: &Options,
) -> Result<()> {
    let auto = o.targets.is_empty();
    let mut targets = o.targets.clone();
    let mut stats = Counts::default();
    let mut cells: HashSet<(u16, Cell)> = HashSet::new();
    let mut failures = 0u32;
    let mut next = 0usize;
    let mut buf = [0u8; 2048];
    if let Some(w) = writer.as_deref_mut() {
        w.prune();
    }

    while !crate::stopping() {
        if targets.is_empty() {
            targets = pick(radio, socket, &mut rep, o)?;
            next = 0;
            continue;
        }
        let hz = targets[next % targets.len()];
        next += 1;
        let label = match freq::hz_to_arfcn(hz) {
            Some(a) => format!("{} (ARFCN {a})", freq::mhz(hz)),
            None => freq::mhz(hz),
        };
        rep.channel(&label);
        scan::drain(socket);
        let mut child = radio.decoder(hz)?;
        let started = Instant::now();
        let (mut last_frame, mut last_flush, mut last_report) = (started, started, started);
        let mut heard = false;

        let outcome = loop {
            if crate::stopping() {
                break "stopping";
            }
            if targets.len() > 1 && started.elapsed() >= o.dwell {
                break "dwell";
            }
            if let Ok(Some(status)) = child.try_wait() {
                rep.warn(&format!("decoder exited ({status}) on {label}"));
                break "failed";
            }
            if last_frame.elapsed() >= o.stall {
                rep.phase(Phase::Stalled);
                rep.warn(&format!(
                    "no frames from {label} for {} s; restarting the decoder",
                    o.stall.as_secs()
                ));
                break "failed";
            }
            if last_flush.elapsed() >= Duration::from_secs(2) {
                if let Some(w) = writer.as_deref_mut() {
                    w.flush()?;
                }
                rep.totals(stats.written, stats.dropped);
                last_flush = Instant::now();
            }
            let every = if matches!(rep, Reporter::Headless) {
                300
            } else {
                30
            };
            if last_report.elapsed() >= Duration::from_secs(every) {
                rep.summary(&stats);
                last_report = Instant::now();
            }
            let Ok(n) = socket.recv(&mut buf) else {
                continue;
            };
            let frame = &buf[..n];
            let Some(header) = gsmtap::header(frame) else {
                continue; // not GSMTAP: something else sent to our port
            };
            last_frame = Instant::now();
            heard = true;
            let kind = gsmtap::kind(frame);
            if let Some(cell) = gsmtap::cell(frame) {
                if cells.insert((header.arfcn, cell.clone())) {
                    rep.cell(header.arfcn, &cell, header.signal_dbm);
                }
            }
            stats.note(&kind);
            rep.frame(&header, frame);
            if o.drop_paging && kind == Kind::Paging {
                stats.dropped += 1;
                continue;
            }
            if let Some(w) = writer.as_deref_mut() {
                w.write(pcapng::now_micros(), frame)?;
                stats.written += 1;
            }
        };

        radio::stop(&mut child);
        if let Some(w) = writer.as_deref_mut() {
            w.flush()?;
        }
        rep.totals(stats.written, stats.dropped);
        if outcome == "failed" {
            failures = if heard { 1 } else { failures + 1 };
            if auto && failures >= 3 {
                rep.warn("the chosen channel(s) stopped working; scanning again");
                targets.clear();
                failures = 0;
            } else if !auto && failures >= 20 {
                bail!("the decoder failed {failures} times in a row without receiving a frame; is the SDR attached and is {label} a GSM broadcast channel?");
            }
            pause(Duration::from_secs(5));
        } else {
            failures = 0;
        }
    }
    rep.phase(Phase::Stopping);
    rep.info(&format!(
        "stopping; {} frames received, {} written, {} dropped, {} cell(s) seen",
        stats.frames(),
        stats.written,
        stats.dropped,
        cells.len()
    ));
    if let Some(w) = writer {
        w.close()?;
    }
    Ok(())
}
