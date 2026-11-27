//! Finding cells: a power sweep picks the channels that carry something,
//! then each is decoded briefly. Only a channel whose broadcast information
//! decodes counts as a cell.

use crate::freq::{self, Band};
use crate::gsmtap::{self, Cell, Kind};
use crate::radio::{self, Power, Radio};
use anyhow::Result;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub arfcn: u16,
    pub hz: u64,
    pub power_db: f64,
}

#[derive(Debug, Clone)]
pub struct Found {
    pub candidate: Candidate,
    /// Broadcast frames decoded during the probe.
    pub frames: usize,
    pub cell: Option<Cell>,
}

/// Channels that stand out of the noise, strongest first. A channel must be
/// at least 6 dB over the median and stronger than both neighbours.
pub fn candidates(power: &[Power], arfcns: &[u16], top: usize) -> Vec<Candidate> {
    let mut levels: Vec<Candidate> = arfcns
        .iter()
        .filter_map(|&arfcn| {
            let hz = freq::arfcn_to_hz(arfcn)?;
            let bins: Vec<f64> = power
                .iter()
                .filter(|(f, _)| (f - hz as f64).abs() <= 75_000.0)
                .map(|(_, db)| *db)
                .collect();
            (!bins.is_empty()).then(|| Candidate {
                arfcn,
                hz,
                power_db: bins.iter().sum::<f64>() / bins.len() as f64,
            })
        })
        .collect();
    if levels.is_empty() {
        return levels;
    }
    let mut sorted: Vec<f64> = levels.iter().map(|c| c.power_db).collect();
    sorted.sort_by(f64::total_cmp);
    let median = sorted[sorted.len() / 2];
    let level_at = |hz: u64| levels.iter().find(|c| c.hz == hz).map(|c| c.power_db);
    let mut peaks: Vec<Candidate> = levels
        .iter()
        .filter(|c| {
            let below = level_at(c.hz - freq::STEP_HZ).unwrap_or(f64::MIN);
            let above = level_at(c.hz + freq::STEP_HZ).unwrap_or(f64::MIN);
            c.power_db >= median + 6.0 && c.power_db >= below && c.power_db > above
        })
        .cloned()
        .collect();
    peaks.sort_by(|a, b| b.power_db.total_cmp(&a.power_db));
    peaks.truncate(top);
    levels.clear();
    peaks
}

/// Throw away frames left over from an earlier decoder.
pub fn drain(socket: &UdpSocket) {
    let mut buf = [0u8; 2048];
    let _ = socket.set_nonblocking(true);
    while socket.recv(&mut buf).is_ok() {}
    let _ = socket.set_nonblocking(false);
}

/// Decode one channel for up to `seconds` and report what was heard. Stops
/// early once the cell has identified itself.
pub fn probe(
    radio: &Radio,
    socket: &UdpSocket,
    hz: u64,
    seconds: u64,
) -> Result<(usize, Option<Cell>)> {
    drain(socket);
    let mut child = radio.decoder(hz)?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let (mut frames, mut cell) = (0usize, None);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && !crate::stopping() && cell.is_none() {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        let Ok(n) = socket.recv(&mut buf) else {
            continue;
        };
        if matches!(gsmtap::kind(&buf[..n]), Kind::SystemInfo(_)) {
            frames += 1;
            cell = gsmtap::cell(&buf[..n]);
        }
    }
    radio::stop(&mut child);
    Ok((frames, cell))
}

/// Sweep the bands, then probe the strongest channels.
pub fn scan(
    radio: &Radio,
    socket: &UdpSocket,
    bands: &[Band],
    top: usize,
    probe_seconds: u64,
) -> Result<Vec<Found>> {
    let mut found = Vec::new();
    for band in bands {
        if crate::stopping() {
            break;
        }
        eprintln!(
            "info: sweeping {} ({} to {})",
            band.name,
            freq::mhz(band.low_hz),
            freq::mhz(band.high_hz)
        );
        let power = match radio.sweep(band.low_hz, band.high_hz) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: {} could not be swept: {e:#}", band.name);
                continue;
            }
        };
        let picks = candidates(&power, &band.arfcns(), top);
        eprintln!(
            "info: {} channel(s) stand out in {}",
            picks.len(),
            band.name
        );
        for c in picks {
            if crate::stopping() {
                break;
            }
            let (frames, cell) = probe(radio, socket, c.hz, probe_seconds)?;
            eprintln!(
                "info: ARFCN {} ({}, {:.1} dB): {}",
                c.arfcn,
                freq::mhz(c.hz),
                c.power_db,
                match &cell {
                    Some(cell) => format!(
                        "cell MCC {} MNC {} LAC {} CID {}",
                        cell.mcc, cell.mnc, cell.lac, cell.cid
                    ),
                    None if frames > 0 => format!("{frames} broadcast frame(s), no identity yet"),
                    None => "no broadcast channel (traffic carrier or not GSM)".into(),
                }
            );
            found.push(Found {
                candidate: c,
                frames,
                cell,
            });
        }
    }
    // Identified cells first, then by power.
    found.sort_by(|a, b| {
        (b.cell.is_some(), b.frames > 0)
            .cmp(&(a.cell.is_some(), a.frames > 0))
            .then(b.candidate.power_db.total_cmp(&a.candidate.power_db))
    });
    Ok(found)
}

/// The scan result as a table for the terminal.
pub fn table(found: &[Found]) -> String {
    let mut out = String::from("ARFCN  FREQUENCY    POWER   MCC  MNC  LAC    CID    BROADCAST\n");
    for f in found {
        let c = &f.candidate;
        let (mcc, mnc, lac, cid) = match &f.cell {
            Some(cell) => (
                cell.mcc.clone(),
                cell.mnc.clone(),
                cell.lac.to_string(),
                cell.cid.to_string(),
            ),
            None => ("-".into(), "-".into(), "-".into(), "-".into()),
        };
        out.push_str(&format!(
            "{:<6} {:<12} {:>5.1}   {:<4} {:<4} {:<6} {:<6} {}\n",
            c.arfcn,
            freq::mhz(c.hz),
            c.power_db,
            mcc,
            mnc,
            lac,
            cid,
            if f.frames > 0 { "yes" } else { "no" }
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flat noise floor with carriers of the given level on some ARFCNs.
    fn spectrum(carriers: &[(u16, f64)]) -> Vec<Power> {
        let mut p = Vec::new();
        let mut hz = 925_012_500.0;
        while hz < 960_000_000.0 {
            let level = carriers
                .iter()
                .find(|(a, _)| (hz - freq::arfcn_to_hz(*a).unwrap() as f64).abs() <= 100_000.0)
                .map(|(_, db)| *db)
                .unwrap_or(-15.0);
            p.push((hz, level));
            hz += 25_000.0;
        }
        p
    }

    #[test]
    fn picks_the_carriers_strongest_first() {
        let arfcns = Band::parse("GSM900").unwrap().arfcns();
        let p = spectrum(&[(11, 3.0), (7, -3.0), (1016, 1.0), (60, -12.0)]);
        let c = candidates(&p, &arfcns, 8);
        let got: Vec<u16> = c.iter().map(|c| c.arfcn).collect();
        // ARFCN 60 is only 3 dB over the floor and is not a candidate.
        assert_eq!(got, vec![11, 1016, 7]);
        assert_eq!(candidates(&p, &arfcns, 1).len(), 1);
        assert!(candidates(&[], &arfcns, 8).is_empty());
        // Nothing stands out of a flat spectrum.
        assert!(candidates(&spectrum(&[]), &arfcns, 8).is_empty());
    }

    #[test]
    fn table_lists_identified_and_silent_channels() {
        let found = vec![
            Found {
                candidate: Candidate {
                    arfcn: 11,
                    hz: 937_200_000,
                    power_db: 3.5,
                },
                frames: 4,
                cell: Some(Cell {
                    mcc: "238".into(),
                    mnc: "01".into(),
                    lac: 431,
                    cid: 1660,
                }),
            },
            Found {
                candidate: Candidate {
                    arfcn: 7,
                    hz: 936_400_000,
                    power_db: -3.0,
                },
                frames: 0,
                cell: None,
            },
        ];
        let t = table(&found);
        assert!(t.contains("11     937.2 MHz"));
        assert!(t.lines().nth(1).unwrap().ends_with("yes"));
        assert!(t.lines().nth(2).unwrap().ends_with("no"));
    }
}
