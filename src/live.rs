//! The interactive view: one readable line per decoded message on standard
//! output, so you can watch what a cell is saying while it is captured.
//!
//! System information repeats several times a second, so each message is
//! shown once and again only when its content changes. Paging and
//! assignments are shown as they happen. Subscriber identities are named by
//! kind only (TMSI, IMSI); the values are in the capture file.

use crate::gsmtap::{self, Assignment, Header, Kind};
use std::collections::HashMap;
use std::io::Write;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[90m";
const DARK_RED: &str = "\x1b[31m";

/// The meaning of a line's colour, kept free of any one display's palette so
/// the stdout view and the TUI can each render it their own way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Broadcast configuration (System Information).
    SystemInfo,
    /// A channel grant.
    Assignment,
    /// A temporary identity was paged.
    Paging,
    /// A permanent identity (IMSI/IMEI) in the clear — worth noticing.
    Alert,
}

impl Tone {
    /// The ANSI colour for the plain stdout view.
    pub fn ansi(self) -> &'static str {
        match self {
            Tone::SystemInfo => "\x1b[96m",
            Tone::Assignment => "\x1b[97m",
            Tone::Paging => "\x1b[93m",
            Tone::Alert => "\x1b[91m",
        }
    }
}

/// What a System Information message is for, in a few words.
fn purpose(message_type: u8) -> &'static str {
    match message_type {
        0x19 => "channels of this cell, access rules",
        0x1A | 0x02 | 0x03 => "neighbour cells to measure",
        0x07 => "3G/4G neighbour cells",
        0x1B => "cell identity, control channel layout",
        0x1C => "location area, cell selection rules",
        0x1D | 0x05 | 0x06 => "neighbour cells (during a call)",
        0x1E => "cell identity (during a call)",
        0x00 => "GPRS / packet data parameters",
        _ => "",
    }
}

/// One line of the view: a short label, its tone, and the detail text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub label: String,
    pub tone: Tone,
    pub detail: String,
}

/// Describe a frame, or `None` for one that is counted but not shown
/// (dedicated-channel frames and paging fillers).
pub fn describe(frame: &[u8]) -> Option<Line> {
    match gsmtap::kind(frame) {
        Kind::SystemInfo(t) => {
            let mut detail = purpose(t).to_string();
            if let Some(c) = gsmtap::cell(frame) {
                detail = format!("MCC {} MNC {} LAC {} CID {}", c.mcc, c.mnc, c.lac, c.cid);
            } else if let Some((mcc, mnc, lac)) = gsmtap::location_area(frame) {
                detail = format!("MCC {mcc} MNC {mnc} LAC {lac}");
            }
            Some(Line {
                label: format!("System Information {}", gsmtap::system_info_name(t)),
                tone: Tone::SystemInfo,
                detail,
            })
        }
        Kind::Paging => {
            let ids = gsmtap::paged(frame);
            if ids.is_empty() {
                return None;
            }
            let permanent = ids.iter().any(|i| *i != "TMSI");
            Some(Line {
                label: "Paging".into(),
                tone: if permanent { Tone::Alert } else { Tone::Paging },
                detail: format!(
                    "{} phone(s) called, by {}{}",
                    ids.len(),
                    ids.join(" + "),
                    if permanent {
                        "  (permanent identity in the clear)"
                    } else {
                        ""
                    }
                ),
            })
        }
        Kind::ImmediateAssignment => Some(Line {
            label: "Immediate Assignment".into(),
            tone: Tone::Assignment,
            detail: match gsmtap::assignment(frame) {
                Some(Assignment::Dedicated { channel, timeslot }) => {
                    format!("a phone is sent to {channel} on timeslot {timeslot}")
                }
                Some(Assignment::Packet) => "a phone gets a packet data (GPRS) resource".into(),
                None => String::new(),
            },
        }),
        Kind::Other => None,
    }
}

/// Remembers which System Information contents have already been shown, so a
/// message that repeats unchanged is not displayed again. Shared by the stdout
/// view and the TUI feed.
#[derive(Default)]
pub struct Dedup {
    shown: HashMap<(u16, u8), Vec<Vec<u8>>>,
}

impl Dedup {
    /// True if this frame is new and should be shown; false if it repeats
    /// content already seen on the same channel and message type. Frames that
    /// are not System Information are always new.
    pub fn is_new(&mut self, header: &Header, frame: &[u8]) -> bool {
        let Kind::SystemInfo(t) = gsmtap::kind(frame) else {
            return true;
        };
        // Some messages are sent as a rotating set of segments, so every
        // distinct content is remembered, not just the latest.
        let body = frame[header.len..].to_vec();
        let seen = self.shown.entry((header.arfcn, t)).or_default();
        if seen.contains(&body) {
            return false;
        }
        if seen.len() >= 32 {
            seen.remove(0);
        }
        seen.push(body);
        true
    }
}

pub struct Live {
    colour: bool,
    dedup: Dedup,
    hidden: u64,
}

impl Live {
    pub fn new(colour: bool) -> Self {
        Self {
            colour,
            dedup: Dedup::default(),
            hidden: 0,
        }
    }

    fn paint(&self, colour: &str, text: &str) -> String {
        if self.colour {
            format!("{colour}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    /// A heading line, e.g. when the channel changes.
    pub fn heading(&mut self, text: &str) {
        let rule = "─".repeat(text.chars().count().min(70));
        println!(
            "\n{}\n{}",
            self.paint(DARK_RED, text),
            self.paint(DIM, &rule)
        );
        let _ = std::io::stdout().flush();
    }

    /// Show one frame, unless it is a repeat or not worth a line.
    pub fn frame(&mut self, header: &Header, frame: &[u8]) {
        let Some(line) = describe(frame) else {
            self.hidden += 1;
            return;
        };
        if !self.dedup.is_new(header, frame) {
            self.hidden += 1;
            return;
        }
        let time = chrono::Local::now().format("%H:%M:%S%.3f").to_string();
        println!(
            "{}  {}  {}  {}  {}",
            self.paint(DIM, &time),
            self.paint(DIM, &format!("ARFCN {:<4}", header.arfcn)),
            self.paint(DIM, &format!("{:>4} dBm", header.signal_dbm)),
            self.paint(line.tone.ansi(), &format!("{:<26}", line.label)),
            line.detail
        );
        let _ = std::io::stdout().flush();
    }

    /// A periodic one-line summary of everything seen so far.
    pub fn summary(&mut self, text: &str) {
        println!(
            "{}",
            self.paint(
                DIM,
                &format!(
                    "  ·· {text}, {} not shown (repeats, fillers, dedicated channels)",
                    self.hidden
                )
            )
        );
        let _ = std::io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gsmtap::tests::{frame, si3};

    #[test]
    fn describes_messages() {
        let l = describe(&si3()).unwrap();
        assert_eq!(l.label, "System Information 3");
        assert_eq!(l.detail, "MCC 238 MNC 01 LAC 431 CID 1660");
        let l = describe(&frame(2, &[0x31, 0x06, 0x1A, 0x00])).unwrap();
        assert_eq!(
            (l.label.as_str(), l.detail.as_str()),
            ("System Information 2", "neighbour cells to measure")
        );

        let l = describe(&frame(2, &[0x25, 0x06, 0x21, 0x00, 0x05, 0xF4, 1, 2, 3, 4])).unwrap();
        assert_eq!(l.detail, "1 phone(s) called, by TMSI");
        // The identity value never appears in the line.
        let l = describe(&frame(
            2,
            &[
                0x4D, 0x06, 0x21, 0x00, 0x08, 0x29, 0x83, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10,
            ],
        ))
        .unwrap();
        assert!(l.detail.contains("IMSI") && l.detail.contains("permanent"));
        assert!(!l.detail.contains("238"));

        let l = describe(&frame(2, &[0x2D, 0x06, 0x3F, 0x00, 0x41, 0x00])).unwrap();
        assert_eq!(l.detail, "a phone is sent to SDCCH/8 on timeslot 1");
    }

    #[test]
    fn fillers_and_dedicated_frames_are_not_shown() {
        assert!(describe(&frame(2, &[0x15, 0x06, 0x21, 0x00, 0x01, 0xF0, 0x2B])).is_none());
        assert!(describe(&frame(7, &[0x01, 0x03, 0x01, 0x2B])).is_none());
    }

    #[test]
    fn repeated_system_information_is_shown_once() {
        let mut live = Live::new(false);
        let p = si3();
        let h = gsmtap::header(&p).unwrap();
        live.frame(&h, &p);
        live.frame(&h, &p);
        assert_eq!(live.hidden, 1);
        // Changed content is shown again.
        let mut changed = p.clone();
        *changed.last_mut().unwrap() ^= 1;
        live.frame(&h, &changed);
        assert_eq!(live.hidden, 1);
        // Going back to content already shown stays quiet.
        live.frame(&h, &p);
        assert_eq!(live.hidden, 2);
    }
}
