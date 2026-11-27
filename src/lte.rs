//! Passive LTE (4G) downlink capture by orchestrating LTESniffer, the same way
//! the rest of cellcap orchestrates gr-gsm. LTESniffer demodulates the LTE
//! downlink control channels (PDCCH/DCI, with PDSCH where unciphered) from a
//! USRP/B210 and writes a MAC-LTE pcap that Wireshark reads directly.
//!
//! cellcap does not reimplement the LTE PHY — that is LTESniffer's job. This
//! module locates the binary, turns cellcap-style options into LTESniffer's
//! command line, runs it in the capture directory, and reports the pcap.
//!
//! Scope, honestly: this is downlink-only on a single SDR (what a B210 does over
//! USB 3.0). Uplink sniffing needs two time-synced SDRs (GPSDO) and is out of
//! scope here. A5/LTE ciphering: control-plane DCI and broadcast are in clear;
//! user-plane PDSCH is only readable when not ciphered.

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

/// The binary we drive, and the pcap it writes into its working directory.
pub const SNIFFER: &str = "LTESniffer";
pub const DL_PCAP: &str = "sniffer_dl_mode.pcap";

/// What to capture and how.
#[derive(Debug, Clone)]
pub struct Job {
    /// Downlink centre frequency in Hz.
    pub freq_hz: u64,
    /// RX antennas: 1 decodes transmission mode 1; 2 allows 2x2 MIMO (TM3/4).
    pub antennas: u8,
    /// Worker threads for the decoder.
    pub threads: u8,
    /// Fixed RX gain in dB, or None for the device's AGC.
    pub gain: Option<f32>,
    /// UHD device arguments passed to LTESniffer's `-a`, e.g. "num_recv_frames=512"
    /// (the B210 needs the larger receive buffer) or "type=b200,num_recv_frames=512".
    pub rf_args: String,
    /// Run cell search (PCI/PRB discovery) before decoding. Off means a fixed cell.
    pub cell_search: bool,
    /// With cell_search off: the physical cell id to lock to.
    pub cell_id: Option<u16>,
    /// With cell_search off: the cell bandwidth in resource blocks (6/15/25/50/75/100).
    pub prb: Option<u16>,
    /// Where the pcap is written.
    pub output_dir: PathBuf,
    /// Show LTESniffer's own output.
    pub verbose: bool,
}

/// Locate the LTESniffer binary. Mirrors radio::find_decoder: an env override,
/// then next to the cellcap binary, then the usual install and build paths,
/// then PATH.
pub fn find_sniffer() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("CELLCAP_LTESNIFFER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "CELLCAP_LTESNIFFER points at {}, which is not a file",
            p.display()
        );
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(SNIFFER);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    for cand in [
        PathBuf::from("/usr/local/bin").join(SNIFFER),
        PathBuf::from("/srv/sdr-tools/LTESniffer/build/src").join(SNIFFER),
    ] {
        if cand.is_file() {
            return Ok(cand);
        }
    }
    crate::radio::which(SNIFFER).ok_or_else(|| {
        anyhow!(
            "LTESniffer was not found. Build it with /srv/sdr-tools/build-ltesniffer.sh, \
             then either install it to /usr/local/bin or set CELLCAP_LTESNIFFER to its path."
        )
    })
}

/// Build the LTESniffer argument list for a downlink capture (mode 0).
/// Kept separate from the spawn so it can be unit-tested.
pub fn argv(job: &Job) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-A".into(),
        job.antennas.to_string(),
        "-W".into(),
        job.threads.to_string(),
        "-f".into(),
        job.freq_hz.to_string(),
        "-m".into(),
        "0".into(), // downlink
    ];
    if job.cell_search {
        a.push("-C".into());
    } else {
        if let Some(id) = job.cell_id {
            a.push("-I".into());
            a.push(id.to_string());
        }
        if let Some(prb) = job.prb {
            a.push("-p".into());
            a.push(prb.to_string());
        }
    }
    if let Some(g) = job.gain {
        a.push("-g".into());
        a.push(format!("{g}"));
    }
    if !job.rf_args.is_empty() {
        a.push("-a".into());
        a.push(job.rf_args.clone());
    }
    a
}

/// Run a downlink capture until interrupted (Ctrl-C / SIGTERM), then report the
/// pcap. LTESniffer writes DL_PCAP into its working directory, so we run it in
/// `output_dir` and move the result to a timestamped name on the way out.
pub fn run(job: &Job) -> Result<()> {
    let bin = find_sniffer()?;
    std::fs::create_dir_all(&job.output_dir)
        .with_context(|| format!("creating {}", job.output_dir.display()))?;

    let argv = argv(job);
    eprintln!(
        "info: LTE downlink at {:.1} MHz via {} ({})",
        job.freq_hz as f64 / 1e6,
        bin.display(),
        if job.cell_search {
            "cell search".to_string()
        } else {
            format!("cell {:?} / {:?} PRB", job.cell_id, job.prb)
        }
    );
    eprintln!("info: writing {} in {}", DL_PCAP, job.output_dir.display());
    eprintln!("info: open it in Wireshark; the downlink is MAC-LTE (filter: mac-lte)");

    // LTESniffer wants real-time scheduling and the SDR; it is normally run as
    // root. We do not escalate here — if it cannot open the device it will say so.
    let mut c = Command::new(&bin);
    c.args(&argv).current_dir(&job.output_dir);
    if job.verbose {
        c.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        c.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let started = Instant::now();
    let mut child = c
        .spawn()
        .with_context(|| format!("starting {}", bin.display()))?;

    // Wait for the user to stop us, or for LTESniffer to exit on its own.
    loop {
        if crate::stopping() {
            crate::radio::stop(&mut child);
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() && started.elapsed().as_secs() < 3 {
                    bail!(
                        "LTESniffer exited immediately ({status}). Common causes: no SDR found \
                         (run uhd_find_devices), needs root for the SDR and real-time priority, \
                         or UHD could not load the FPGA image."
                    );
                }
                break;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(200)),
            Err(e) => bail!("waiting on LTESniffer: {e}"),
        }
    }

    // Report / rename the pcap.
    let produced = job.output_dir.join(DL_PCAP);
    if produced.is_file() {
        let stamp = chrono_stamp();
        let dest = job.output_dir.join(format!("lte_dl_{stamp}.pcapng.pcap"));
        match std::fs::rename(&produced, &dest) {
            Ok(_) => {
                let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                eprintln!("info: captured {} ({} KiB)", dest.display(), size / 1024);
            }
            Err(_) => eprintln!("info: captured {}", produced.display()),
        }
    } else {
        eprintln!(
            "warning: no {} was written — LTESniffer may not have locked onto a cell",
            DL_PCAP
        );
    }
    Ok(())
}

/// A filesystem-safe UTC timestamp, without pulling in a date crate.
fn chrono_stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.to_string()
}

/// Convert an E-UTRA Absolute Radio Frequency Channel Number (downlink) to a
/// centre frequency in Hz, for the common FDD bands (3GPP TS 36.101 Table
/// 5.7.3-1). Returns None for an EARFCN outside the listed bands.
///
///   F_DL = F_DL_low + 0.1 * (EARFCN - N_Offs_DL)   [MHz]
pub fn earfcn_to_hz(earfcn: u32) -> Option<u64> {
    // (band, earfcn_low, earfcn_high, f_dl_low_mhz, n_offs_dl)
    const BANDS: &[(u8, u32, u32, f64, u32)] = &[
        (1, 0, 599, 2110.0, 0),
        (2, 600, 1199, 1930.0, 600),
        (3, 1200, 1949, 1805.0, 1200),
        (4, 1950, 2399, 2110.0, 1950),
        (5, 2400, 2649, 869.0, 2400),
        (7, 2750, 3449, 2620.0, 2750),
        (8, 3450, 3799, 925.0, 3450),
        (12, 5010, 5179, 729.0, 5010),
        (13, 5180, 5279, 746.0, 5180),
        (20, 6150, 6449, 791.0, 6150),
        (25, 8040, 8689, 1930.0, 8040),
        (26, 8690, 9039, 859.0, 8690),
        (28, 9210, 9659, 758.0, 9210),
        (66, 66436, 67335, 2110.0, 66436),
    ];
    for &(_band, lo, hi, f_low, offs) in BANDS {
        if earfcn >= lo && earfcn <= hi {
            let f_mhz = f_low + 0.1 * (earfcn - offs) as f64;
            return Some((f_mhz * 1e6).round() as u64);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earfcn_maps_common_bands() {
        // Band 3 (1800 DL), EARFCN 1575 -> 1842.5 MHz.
        assert_eq!(earfcn_to_hz(1575), Some(1_842_500_000));
        // Band 1 (2100 DL), EARFCN 300 -> 2140.0 MHz.
        assert_eq!(earfcn_to_hz(300), Some(2_140_000_000));
        // Band 20 (800 DL), EARFCN 6300 -> 806.0 MHz.
        assert_eq!(earfcn_to_hz(6300), Some(806_000_000));
        // Band 7 (2600 DL), EARFCN 3100 -> 2655.0 MHz.
        assert_eq!(earfcn_to_hz(3100), Some(2_655_000_000));
        // Outside any listed band.
        assert_eq!(earfcn_to_hz(70000), None);
    }

    #[test]
    fn argv_downlink_cell_search() {
        let job = Job {
            freq_hz: 1_842_500_000,
            antennas: 2,
            threads: 4,
            gain: None,
            rf_args: "num_recv_frames=512".into(),
            cell_search: true,
            cell_id: None,
            prb: None,
            output_dir: "/tmp".into(),
            verbose: false,
        };
        let a = argv(&job).join(" ");
        assert!(a.contains("-f 1842500000"));
        assert!(a.contains("-m 0"));
        assert!(a.contains("-C"));
        assert!(a.contains("-A 2"));
        assert!(a.contains("-a num_recv_frames=512"));
        // No fixed cell flags when searching.
        assert!(!a.contains("-I"));
    }

    #[test]
    fn argv_fixed_cell_with_gain() {
        let job = Job {
            freq_hz: 806_000_000,
            antennas: 1,
            threads: 2,
            gain: Some(40.0),
            rf_args: String::new(),
            cell_search: false,
            cell_id: Some(379),
            prb: Some(100),
            output_dir: "/tmp".into(),
            verbose: false,
        };
        let a = argv(&job).join(" ");
        assert!(a.contains("-I 379"));
        assert!(a.contains("-p 100"));
        assert!(a.contains("-g 40"));
        assert!(!a.contains("-C"));
        assert!(!a.contains("-a ")); // empty rf_args omitted
    }
}
