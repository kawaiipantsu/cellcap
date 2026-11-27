//! Shared state between the capture loop and the interactive TUI.
//!
//! The capture loop runs on its own thread and writes what it sees here; the
//! TUI, on the main thread, takes a snapshot each time it draws. One mutex
//! guards everything: updates and reads are both short, and frames are drawn a
//! few times a second, so contention is not a concern.

use crate::gsmtap::{self, Cell, Header, Kind};
use crate::live::{self, Dedup, Tone};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

/// How many lines of the live feed and the log to keep.
const FEED_CAP: usize = 2000;
const LOG_CAP: usize = 1000;

/// Running frame counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counts {
    pub system_info: u64,
    pub paging: u64,
    pub assignments: u64,
    pub other: u64,
    pub written: u64,
    pub dropped: u64,
}

impl Counts {
    pub fn frames(&self) -> u64 {
        self.system_info + self.paging + self.assignments + self.other
    }

    pub fn note(&mut self, kind: &Kind) {
        match kind {
            Kind::SystemInfo(_) => self.system_info += 1,
            Kind::Paging => self.paging += 1,
            Kind::ImmediateAssignment => self.assignments += 1,
            Kind::Other => self.other += 1,
        }
    }
}

/// What the capture loop is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Scanning,
    Capturing,
    Stalled,
    Stopping,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Starting => "starting",
            Phase::Scanning => "scanning",
            Phase::Capturing => "capturing",
            Phase::Stalled => "stalled",
            Phase::Stopping => "stopping",
        }
    }
}

/// Severity of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub text: String,
}

/// One line of the decoded-message feed.
#[derive(Debug, Clone)]
pub struct FeedLine {
    pub time: String,
    pub arfcn: u16,
    pub dbm: i8,
    pub tone: Tone,
    pub label: String,
    pub detail: String,
}

/// A cell seen during this run, with how often and how strongly.
#[derive(Debug, Clone)]
pub struct CellStat {
    pub arfcn: u16,
    pub cell: Cell,
    pub signal_dbm: i8,
    pub frames: u64,
}

struct Inner {
    started: Instant,
    device: String,
    output: Option<String>,
    phase: Phase,
    channel: String,
    counts: Counts,
    hidden: u64,
    cells: BTreeMap<(u16, u16, u16), CellStat>,
    feed: VecDeque<FeedLine>,
    log: VecDeque<LogLine>,
    dedup: Dedup,
}

/// A point-in-time copy of everything the TUI draws.
pub struct Snapshot {
    pub uptime: std::time::Duration,
    pub device: String,
    pub output: Option<String>,
    pub phase: Phase,
    pub channel: String,
    pub counts: Counts,
    pub hidden: u64,
    pub cells: Vec<CellStat>,
    pub feed: Vec<FeedLine>,
    pub log: Vec<LogLine>,
}

pub struct Model {
    inner: Mutex<Inner>,
}

impl Model {
    pub fn new(device: String, output: Option<String>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                started: Instant::now(),
                device,
                output,
                phase: Phase::Starting,
                channel: String::new(),
                counts: Counts::default(),
                hidden: 0,
                cells: BTreeMap::new(),
                feed: VecDeque::new(),
                log: VecDeque::new(),
                dedup: Dedup::default(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A thread never panics while holding the lock, so a poisoned lock
        // cannot happen; recover the guard rather than propagate if it does.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now() -> String {
        chrono::Local::now().format("%H:%M:%S%.3f").to_string()
    }

    pub fn set_phase(&self, phase: Phase) {
        self.lock().phase = phase;
    }

    pub fn set_channel(&self, channel: &str) {
        let mut g = self.lock();
        g.channel = channel.to_string();
        g.phase = Phase::Capturing;
    }

    pub fn log(&self, level: Level, text: &str) {
        let line = LogLine {
            time: Self::now(),
            level,
            text: text.to_string(),
        };
        let mut g = self.lock();
        g.log.push_back(line);
        while g.log.len() > LOG_CAP {
            g.log.pop_front();
        }
    }

    /// Record a decoded frame: count it, remember the cell, and add a feed
    /// line unless it only repeats System Information already shown.
    pub fn frame(&self, header: &Header, frame: &[u8]) {
        let kind = gsmtap::kind(frame);
        let mut g = self.lock();
        g.counts.note(&kind);

        if let Some(cell) = gsmtap::cell(frame) {
            let key = (header.arfcn, cell.lac, cell.cid);
            g.cells
                .entry(key)
                .and_modify(|c| {
                    c.signal_dbm = header.signal_dbm;
                    c.frames += 1;
                })
                .or_insert(CellStat {
                    arfcn: header.arfcn,
                    cell,
                    signal_dbm: header.signal_dbm,
                    frames: 1,
                });
        }

        let Some(line) = live::describe(frame) else {
            return;
        };
        if !g.dedup.is_new(header, frame) {
            g.hidden += 1;
            return;
        }
        let feed = FeedLine {
            time: Self::now(),
            arfcn: header.arfcn,
            dbm: header.signal_dbm,
            tone: line.tone,
            label: line.label,
            detail: line.detail,
        };
        g.feed.push_back(feed);
        while g.feed.len() > FEED_CAP {
            g.feed.pop_front();
        }
    }

    pub fn set_written(&self, written: u64, dropped: u64) {
        let mut g = self.lock();
        g.counts.written = written;
        g.counts.dropped = dropped;
    }

    pub fn snapshot(&self) -> Snapshot {
        let g = self.lock();
        let mut cells: Vec<CellStat> = g.cells.values().cloned().collect();
        cells.sort_by(|a, b| b.frames.cmp(&a.frames).then(a.arfcn.cmp(&b.arfcn)));
        Snapshot {
            uptime: g.started.elapsed(),
            device: g.device.clone(),
            output: g.output.clone(),
            phase: g.phase,
            channel: g.channel.clone(),
            counts: g.counts,
            hidden: g.hidden,
            cells,
            feed: g.feed.iter().cloned().collect(),
            log: g.log.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gsmtap::tests::{frame, si3};

    #[test]
    fn counts_and_cells_accumulate() {
        let m = Model::new("rtl=0".into(), Some("/tmp".into()));
        let p = si3();
        let h = gsmtap::header(&p).unwrap();
        m.frame(&h, &p);
        m.frame(&h, &p); // repeat: counted, but not a second feed line
        let s = m.snapshot();
        assert_eq!(s.counts.system_info, 2);
        assert_eq!(s.counts.frames(), 2);
        assert_eq!(s.feed.len(), 1);
        assert_eq!(s.hidden, 1);
        assert_eq!(s.cells.len(), 1);
        assert_eq!(s.cells[0].frames, 2);
        assert_eq!(s.cells[0].cell.mcc, "238");
    }

    #[test]
    fn paging_makes_a_feed_line_without_a_cell() {
        let m = Model::new("rtl=0".into(), None);
        let pg = frame(2, &[0x25, 0x06, 0x21, 0x00, 0x05, 0xF4, 1, 2, 3, 4]);
        let h = gsmtap::header(&pg).unwrap();
        m.frame(&h, &pg);
        let s = m.snapshot();
        assert_eq!(s.counts.paging, 1);
        assert_eq!(s.feed.len(), 1);
        assert_eq!(s.feed[0].tone, Tone::Paging);
        assert!(s.cells.is_empty());
    }

    #[test]
    fn log_is_bounded() {
        let m = Model::new("rtl=0".into(), None);
        for i in 0..(LOG_CAP + 50) {
            m.log(Level::Info, &format!("line {i}"));
        }
        assert_eq!(m.snapshot().log.len(), LOG_CAP);
    }
}
