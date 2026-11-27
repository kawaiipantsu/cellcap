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
    /// A permanent identity (IMSI/IMEI) in the clear, or a reject — worth noticing.
    Alert,
    /// Mobility / connection-management signalling (Location Updating, CM service…).
    Signalling,
    /// Security exchange (authentication, ciphering, identity).
    Security,
    /// Short message service.
    Sms,
    /// Call control (setup, alerting, connect, release).
    Call,
}

impl Tone {
    /// The ANSI colour for the plain stdout view.
    pub fn ansi(self) -> &'static str {
        match self {
            Tone::SystemInfo => "\x1b[96m",
            Tone::Assignment => "\x1b[97m",
            Tone::Paging => "\x1b[93m",
            Tone::Alert => "\x1b[91m",
            Tone::Signalling => "\x1b[94m",
            Tone::Security => "\x1b[95m",
            Tone::Sms => "\x1b[92m",
            Tone::Call => "\x1b[36m",
        }
    }
}

/// Map a dedicated-channel L3 message (protocol discriminator + message type) to
/// a readable event and its tone. Best-effort, for the live view. Returns a
/// generic label for a recognised protocol with an unmapped type.
fn dtap_event(pd: u8, mt: u8) -> Option<(&'static str, Tone)> {
    use Tone::*;
    Some(match (pd, mt) {
        // Mobility management (TS 24.008 §10.4)
        (0x05, 0x08) => ("Location Updating Request", Signalling),
        (0x05, 0x02) => ("Location Updating Accept", Signalling),
        (0x05, 0x04) => ("Location Updating Reject", Alert),
        (0x05, 0x01) => ("IMSI Detach Indication", Signalling),
        (0x05, 0x12) => ("Authentication Request", Security),
        (0x05, 0x14) => ("Authentication Response", Security),
        (0x05, 0x1C) => ("Authentication Reject", Alert),
        (0x05, 0x18) => ("Identity Request", Security),
        (0x05, 0x19) => ("Identity Response", Security),
        (0x05, 0x1A) => ("TMSI Reallocation Command", Signalling),
        (0x05, 0x1B) => ("TMSI Reallocation Complete", Signalling),
        (0x05, 0x24) => ("CM Service Request", Signalling),
        (0x05, 0x21) => ("CM Service Accept", Signalling),
        (0x05, 0x22) => ("CM Service Reject", Alert),
        (0x05, 0x32) => ("MM Information (name / time)", Signalling),
        (0x05, _) => ("Mobility Management", Signalling),
        // Radio resource (TS 44.018)
        (0x06, 0x35) => ("Ciphering Mode Command", Security),
        (0x06, 0x32) => ("Ciphering Mode Complete", Security),
        (0x06, 0x2E) => ("Assignment Command", Assignment),
        (0x06, 0x29) => ("Assignment Complete", Assignment),
        (0x06, 0x2F) => ("Assignment Failure", Alert),
        (0x06, 0x2B) => ("Handover Command", Assignment),
        (0x06, 0x0D) => ("Channel Release", Signalling),
        (0x06, 0x3A) => ("Channel Mode Modify", Signalling),
        (0x06, 0x15) => ("Measurement Report", Signalling),
        (0x06, 0x16) => ("Classmark Change", Signalling),
        (0x06, 0x13) => ("Classmark Enquiry", Signalling),
        (0x06, _) => ("Radio Resource", Signalling),
        // Call control (TS 24.008 §10.4)
        (0x03, 0x05) => ("Call Setup", Call),
        (0x03, 0x02) => ("Call Proceeding", Call),
        (0x03, 0x01) => ("Alerting (ringing)", Call),
        (0x03, 0x07) => ("Connect (answered)", Call),
        (0x03, 0x0F) => ("Connect Acknowledge", Call),
        (0x03, 0x25) => ("Disconnect", Call),
        (0x03, 0x2D) => ("Release", Call),
        (0x03, 0x2A) => ("Release Complete", Call),
        (0x03, 0x3E) => ("Emergency Call Setup", Alert),
        (0x03, _) => ("Call Control", Call),
        // Short messages (CP layer)
        (0x09, 0x01) => ("SMS (CP-DATA)", Sms),
        (0x09, 0x04) => ("SMS (CP-ACK)", Sms),
        (0x09, 0x10) => ("SMS (CP-ERROR)", Sms),
        (0x09, _) => ("Short Message", Sms),
        // Supplementary services
        (0x0B, _) => ("Supplementary Service", Signalling),
        // GPRS mobility / session management
        (0x08, _) => ("GPRS Mobility Management", Signalling),
        (0x0A, _) => ("GPRS Session Management", Signalling),
        _ => return None,
    })
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

/// A readable PLMN: "TDC A/S · Denmark · 238/01", or just "238/01" when the
/// operator and country are unknown. Always keeps the raw codes for verification.
pub fn pretty_plmn(mcc: &str, mnc: &str) -> String {
    let name = crate::e212::describe(mcc, mnc);
    if name.is_empty() {
        format!("{mcc}/{mnc}")
    } else {
        format!("{name} · {mcc}/{mnc}")
    }
}

/// What kind of data a dedicated-channel message carries, in a few words, for
/// the detail column. Best-effort and byte-guarded; empty when there is nothing
/// cheap and useful to add. `l3` starts at the protocol-discriminator octet.
fn dtap_detail(pd: u8, mt: u8, l3: &[u8]) -> String {
    match (pd, mt) {
        // Identity Request: the network asks for a specific identity — showing
        // IMSI/IMEI here is a classic IMSI-catcher tell.
        (0x05, 0x18) => match l3.get(2).copied().and_then(gsmtap::identity_name) {
            Some(id) => format!("asks for {id}"),
            None => String::new(),
        },
        // TMSI Reallocation / Location Updating Accept: a new identity is assigned.
        (0x05, 0x1A) => match l3.get(8).copied().and_then(gsmtap::identity_name) {
            Some(id) => format!("assigns {id}"),
            None => "assigns a new identity".into(),
        },
        (0x05, 0x12) => "128-bit RAND challenge".into(),
        (0x05, 0x32) => "network name / time".into(),
        // Ciphering Mode Command: octet 3 bit 0 = start/stop, bits 1-3 = A5 algo.
        (0x06, 0x35) => match l3.get(2) {
            Some(o) if o & 0x01 == 0 => "no ciphering".into(),
            Some(o) => format!("start A5/{}", ((o >> 1) & 0x07) + 1),
            None => String::new(),
        },
        (0x03, 0x05) => "incoming call".into(),
        (0x09, 0x01) => "message delivery".into(),
        _ => String::new(),
    }
}

/// Describe a frame, or `None` for one that is counted but not shown
/// (dedicated-channel frames and paging fillers).
pub fn describe(frame: &[u8]) -> Option<Line> {
    match gsmtap::kind(frame) {
        Kind::SystemInfo(t) => {
            let mut detail = purpose(t).to_string();
            if let Some(c) = gsmtap::cell(frame) {
                detail = format!("{} · LAC {} CID {}", pretty_plmn(&c.mcc, &c.mnc), c.lac, c.cid);
            } else if let Some((mcc, mnc, lac)) = gsmtap::location_area(frame) {
                detail = format!("{} · LAC {lac}", pretty_plmn(&mcc, &mnc));
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
        Kind::Other => {
            // Signalling on a dedicated channel (SDCCH/SACCH/FACCH): show the event
            // and, where cheap to read, what kind of data it carries.
            let (pd, mt, l3) = gsmtap::l3_dedicated(frame)?;
            let (label, tone) = dtap_event(pd, mt)?;
            Some(Line {
                label: label.to_string(),
                tone,
                detail: dtap_detail(pd, mt, l3),
            })
        }
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
            "{}  {}  {}  {}  {}  {}",
            self.paint(DIM, &time),
            self.paint(DIM, &format!("ARFCN {:<4}", header.arfcn)),
            self.paint(DIM, &format!("{:>4} dBm", header.signal_dbm)),
            self.paint(DIM, &format!("{:<9}", crate::inspect::channel_name(header.channel))),
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
        // PLMN name comes from the E.212 table via pretty_plmn — not duplicated here.
        assert_eq!(l.detail, format!("{} · LAC 431 CID 1660", pretty_plmn("238", "01")));
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

    #[test]
    fn dedicated_events_name_the_data() {
        // Identity Request asking for the IMSI (l3[2] type = 1).
        assert_eq!(dtap_detail(0x05, 0x18, &[0x05, 0x18, 0x01]), "asks for IMSI");
        // Ciphering Mode Command: SC=1 (start), algo bits = 0 -> A5/1.
        assert_eq!(dtap_detail(0x06, 0x35, &[0x06, 0x35, 0x01]), "start A5/1");
        // SC=0 -> no ciphering.
        assert_eq!(dtap_detail(0x06, 0x35, &[0x06, 0x35, 0x00]), "no ciphering");
        // Authentication Request always carries a RAND.
        assert_eq!(dtap_detail(0x05, 0x12, &[0x05, 0x12]), "128-bit RAND challenge");
        // A message with nothing extra to say.
        assert_eq!(dtap_detail(0x06, 0x0D, &[0x06, 0x0D]), "");
    }
}
