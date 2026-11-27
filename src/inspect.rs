//! Read a capture file back and summarise it, the way `tshark -z` would: how
//! many frames of each kind, which channels and cells, and the time span. It
//! needs no radio, so it is the quick way to check a file holds what you want
//! before opening Wireshark.

use crate::gsmtap::{self, Kind};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Everything counted while walking one file.
#[derive(Default)]
struct Summary {
    packets: u64,
    system_info: BTreeMap<String, u64>,
    paging: u64,
    assignment: u64,
    other: u64,
    channels: BTreeMap<u8, u64>,
    cells: BTreeMap<(u16, u16, u16), (String, String)>,
    first_us: Option<u64>,
    last_us: Option<u64>,
}

/// Pull the GSMTAP frame out of one exported-PDU record: skip the leading
/// option tags (each a big-endian code and length) up to the end-of-options
/// tag, and return what follows.
fn gsmtap_of(data: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    loop {
        let tag = u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]);
        let len = u16::from_be_bytes([*data.get(at + 2)?, *data.get(at + 3)?]) as usize;
        at += 4;
        if tag == 0 {
            return data.get(at..);
        }
        at += len;
    }
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

impl Summary {
    fn record(&mut self, timestamp_us: u64, frame: &[u8]) {
        self.packets += 1;
        self.first_us = Some(self.first_us.map_or(timestamp_us, |v| v.min(timestamp_us)));
        self.last_us = Some(self.last_us.map_or(timestamp_us, |v| v.max(timestamp_us)));
        if let Some(h) = gsmtap::header(frame) {
            *self.channels.entry(h.channel).or_default() += 1;
        }
        match gsmtap::kind(frame) {
            Kind::SystemInfo(t) => {
                *self
                    .system_info
                    .entry(gsmtap::system_info_name(t))
                    .or_default() += 1
            }
            Kind::Paging => self.paging += 1,
            Kind::ImmediateAssignment => self.assignment += 1,
            Kind::Other => self.other += 1,
        }
        if let Some(c) = gsmtap::cell(frame) {
            self.cells
                .entry((h_arfcn(frame), c.lac, c.cid))
                .or_insert((c.mcc, c.mnc));
        }
    }
}

fn h_arfcn(frame: &[u8]) -> u16 {
    gsmtap::header(frame).map(|h| h.arfcn).unwrap_or(0)
}

/// Walk the pcapng blocks of one file and count what they carry.
fn read(bytes: &[u8]) -> Result<Summary> {
    let mut s = Summary::default();
    let mut at = 0;
    while at + 8 <= bytes.len() {
        let kind = u32le(bytes, at).context("truncated block header")?;
        let total = u32le(bytes, at + 4).context("truncated block length")? as usize;
        if total < 12 || at + total > bytes.len() {
            bail!("not a pcapng file, or it is truncated");
        }
        // Enhanced Packet Block: interface, timestamp, lengths, then data.
        if kind == 6 {
            let body = &bytes[at + 8..at + total - 4];
            let (ts_high, ts_low, cap_len) = (
                u32le(body, 4).unwrap_or(0) as u64,
                u32le(body, 8).unwrap_or(0) as u64,
                u32le(body, 12).unwrap_or(0) as usize,
            );
            let ts = (ts_high << 32) | ts_low;
            if let Some(data) = body.get(20..20 + cap_len) {
                if let Some(frame) = gsmtap_of(data) {
                    s.record(ts, frame);
                }
            }
        }
        at += total;
    }
    Ok(s)
}

fn when(us: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_micros(us as i64)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "?".into())
}

/// Summarise one file as text for the terminal.
pub fn report(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let s = read(&bytes)?;
    let mut out = String::new();
    out.push_str(&format!("{}\n", path.display()));
    out.push_str(&format!(
        "  {} bytes, {} GSMTAP frame(s)\n",
        bytes.len(),
        s.packets
    ));
    if let (Some(a), Some(b)) = (s.first_us, s.last_us) {
        let span = (b.saturating_sub(a)) as f64 / 1e6;
        out.push_str(&format!(
            "  from {} to {}  ({:.1} s)\n",
            when(a),
            when(b),
            span
        ));
    }
    out.push_str("  by message:\n");
    let si_total: u64 = s.system_info.values().sum();
    out.push_str(&format!("    System Information   {si_total}\n"));
    for (name, n) in &s.system_info {
        out.push_str(&format!("      type {name:<8}       {n}\n"));
    }
    out.push_str(&format!("    Paging               {}\n", s.paging));
    out.push_str(&format!("    Immediate Assignment {}\n", s.assignment));
    out.push_str(&format!("    Other                {}\n", s.other));
    out.push_str("  by channel:\n");
    for (ch, n) in &s.channels {
        out.push_str(&format!("    {:<20} {n}\n", channel_name(*ch)));
    }
    if s.cells.is_empty() {
        out.push_str("  cells: none identified\n");
    } else {
        out.push_str("  cells:\n");
        for ((arfcn, lac, cid), (mcc, mnc)) in &s.cells {
            out.push_str(&format!(
                "    ARFCN {arfcn:<5} MCC {mcc} MNC {mnc} LAC {lac} CID {cid}\n"
            ));
        }
    }
    Ok(out)
}

/// The GSMTAP channel-type number as a name. Bit 0x80 marks the slow
/// associated control channel (SACCH) riding on the base channel.
pub fn channel_name(ch: u8) -> String {
    let base = match ch & 0x7F {
        0x01 => "BCCH",
        0x02 => "CCCH",
        0x03 => "RACH",
        0x04 => "AGCH",
        0x05 => "PCH",
        0x06 => "SDCCH",
        0x07 => "SDCCH/4",
        0x08 => "SDCCH/8",
        0x09 => "TCH/F",
        0x0A => "TCH/H",
        0x0B => "PACCH",
        0x0C => "CBCH(52)",
        0x0D => "PDTCH",
        0x0E => "PTCCH",
        0x0F => "CBCH(51)",
        _ => return format!("channel 0x{ch:02X}"),
    };
    if ch & 0x80 != 0 {
        format!("SACCH/{base}")
    } else {
        base.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gsmtap::tests::si3;
    use crate::pcapng;

    #[test]
    fn summarises_a_written_file() {
        let mut bytes = pcapng::file_header("test");
        bytes.extend(pcapng::packet(1_700_000_000_000_000, &si3()));
        bytes.extend(pcapng::packet(
            1_700_000_002_000_000,
            &crate::gsmtap::tests::frame(2, &[0x25, 0x06, 0x21, 0x00, 0x05, 0xF4, 1, 2, 3, 4]),
        ));
        let s = read(&bytes).unwrap();
        assert_eq!(s.packets, 2);
        assert_eq!(s.system_info.get("3"), Some(&1));
        assert_eq!(s.paging, 1);
        assert_eq!(s.cells.len(), 1);
        let span = s.last_us.unwrap() - s.first_us.unwrap();
        assert_eq!(span, 2_000_000);
    }

    #[test]
    fn rejects_non_pcapng() {
        assert!(read(b"not a capture at all").is_err());
    }
}
