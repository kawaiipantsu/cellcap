//! The radio side: gr-gsm does the demodulation and channel decoding and
//! hands the frames over as GSMTAP on a local UDP port; the SDR vendor tools
//! measure power for the scan.

use anyhow::{anyhow, bail, Context, Result};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A dedicated/control channel decoding mode, as `grgsm_decode -m` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    Bcch,
    BcchSdcch4,
    Sdcch8,
    Tchf,
    Tchh,
}

impl DecodeMode {
    pub fn flag(self) -> &'static str {
        match self {
            DecodeMode::Bcch => "BCCH",
            DecodeMode::BcchSdcch4 => "BCCH_SDCCH4",
            DecodeMode::Sdcch8 => "SDCCH8",
            DecodeMode::Tchf => "TCHF",
            DecodeMode::Tchh => "TCHH",
        }
    }
}

/// The A5 cipher and its session key, for decoding ciphered channels.
#[derive(Debug, Clone)]
pub struct Cipher {
    /// A5 version (1, 2 or 3).
    pub a5: u8,
    /// The session key Kc, as grgsm_decode accepts it (hex or 0x,.. bytes).
    pub kc: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    RtlSdr,
    HackRf,
    Other,
}

#[derive(Debug, Clone)]
pub struct Radio {
    /// gr-osmosdr device arguments, e.g. `rtl=0` or `hackrf=0`.
    pub device: String,
    pub gain: f32,
    pub ppm: i32,
    /// Local UDP port the decoder sends GSMTAP to. The decoder itself
    /// binds the next port up.
    pub port: u16,
    /// Show the decoder's own output instead of discarding it.
    pub verbose: bool,
}

/// One power measurement: centre frequency and level in dB.
pub type Power = (f64, f64);

/// A cell reported by grgsm_scanner.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannedCell {
    pub arfcn: u16,
    pub freq_hz: u64,
    pub cid: u16,
    pub lac: u16,
    pub mcc: u16,
    pub mnc: u16,
    pub power_db: f64,
}

/// Parse grgsm_scanner output, keeping its cell lines. Each is formatted
/// `ARFCN: %4u, Freq: %6.1fM, CID: %5u, LAC: %5u, MCC: %3u, MNC: %3u, Pwr: %3i`.
pub fn parse_scanner(out: &str) -> Vec<ScannedCell> {
    out.lines().filter_map(parse_scanner_line).collect()
}

fn parse_scanner_line(line: &str) -> Option<ScannedCell> {
    if !line.contains("ARFCN:") || !line.contains("Freq:") {
        return None;
    }
    let mut arfcn = None;
    let mut freq_hz = None;
    let mut cid = None;
    let mut lac = None;
    let mut mcc = None;
    let mut mnc = None;
    let mut pwr = None;
    for field in line.split(',') {
        let (key, value) = field.split_once(':')?;
        let value = value.trim();
        match key.trim() {
            "ARFCN" => arfcn = value.parse().ok(),
            "Freq" => {
                freq_hz = value
                    .trim_end_matches('M')
                    .parse::<f64>()
                    .ok()
                    .map(|mhz| (mhz * 1e6).round() as u64)
            }
            "CID" => cid = value.parse().ok(),
            "LAC" => lac = value.parse().ok(),
            "MCC" => mcc = value.parse().ok(),
            "MNC" => mnc = value.parse().ok(),
            "Pwr" => pwr = value.parse().ok(),
            _ => {}
        }
    }
    Some(ScannedCell {
        arfcn: arfcn?,
        freq_hz: freq_hz?,
        cid: cid?,
        lac: lac?,
        mcc: mcc?,
        mnc: mnc?,
        power_db: pwr?,
    })
}

impl Radio {
    pub fn kind(&self) -> Kind {
        let d = self.device.to_ascii_lowercase();
        if d.starts_with("rtl") {
            Kind::RtlSdr
        } else if d.starts_with("hackrf") {
            Kind::HackRf
        } else {
            Kind::Other
        }
    }

    /// Index after `rtl=` / `hackrf=`, when the device is given that way.
    fn index(&self) -> Option<&str> {
        let first = self.device.split(',').next()?;
        let (_, v) = first.split_once('=')?;
        v.chars().all(|c| c.is_ascii_digit()).then_some(v)
    }

    /// Start the decoder on one channel. It runs until stopped.
    pub fn decoder(&self, hz: u64) -> Result<Child> {
        let mut c = Command::new("grgsm_livemon_headless");
        c.arg("--args")
            .arg(&self.device)
            .arg("-f")
            .arg(hz.to_string())
            .arg("-g")
            .arg(self.gain.to_string())
            .arg("-p")
            .arg(self.ppm.to_string())
            .arg("--collector")
            .arg("127.0.0.1")
            .arg("--collectorport")
            .arg(self.port.to_string())
            // The decoder also opens a UDP server of its own; keep it off
            // the standard GSMTAP port and next to ours.
            .arg("--serverport")
            .arg(self.port.wrapping_add(1).to_string())
            .stdin(Stdio::null())
            // The decoder prints every frame as hex on stdout.
            .stdout(Stdio::null())
            .stderr(if self.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        die_with_parent(&mut c);
        c.spawn().context(
            "starting grgsm_livemon_headless (is gr-gsm installed? Debian: apt install gr-gsm)",
        )
    }

    /// Record raw samples of one channel to a cfile for later decoding.
    /// Uses `grgsm_capture`, which drives the osmosdr source like the decoder.
    pub fn record(&self, hz: u64, seconds: u64, samp_rate: u64, out: &Path) -> Result<()> {
        let mut c = Command::new("grgsm_capture");
        c.arg("-f")
            .arg(hz.to_string())
            .arg("-g")
            .arg(self.gain.to_string())
            .arg("-s")
            .arg(samp_rate.to_string())
            .arg("-p")
            .arg(self.ppm.to_string())
            .arg("-T")
            .arg(seconds.to_string())
            .arg("--args")
            .arg(&self.device)
            .arg(out)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(if self.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        die_with_parent(&mut c);
        let mut child = c
            .spawn()
            .context("starting grgsm_capture (is gr-gsm installed? Debian: apt install gr-gsm)")?;
        // grgsm_capture stops itself after the recording length.
        let deadline = Instant::now() + Duration::from_secs(seconds + 30);
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    bail!("grgsm_capture failed ({status}); re-run with --verbose-radio");
                }
                break;
            }
            if Instant::now() > deadline || crate::stopping() {
                stop(&mut child);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    /// Decode a recorded cfile on a dedicated/control channel and deliver the
    /// GSMTAP to our collector. It runs to the end of the file, then exits.
    ///
    /// `collector_port` is where cellcap listens; the decoder binds its own
    /// server one port higher, so the two never clash.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        &self,
        cfile: &Path,
        hz: u64,
        samp_rate: u64,
        mode: DecodeMode,
        timeslot: u8,
        subslot: Option<u8>,
        cipher: Option<&Cipher>,
        collector_port: u16,
    ) -> Result<Child> {
        let decoder = find_decoder()?;
        let mut c = Command::new(&decoder);
        c.arg("-c").arg(cfile);
        // Prefer -a (ARFCN) so the decoder stamps the right ARFCN into GSMTAP;
        // fall back to the raw frequency for channels outside the ARFCN tables.
        match crate::freq::hz_to_arfcn(hz) {
            Some(arfcn) => {
                c.arg("-a").arg(arfcn.to_string());
            }
            None => {
                c.arg("-f").arg(hz.to_string());
            }
        }
        c.arg("-s")
            .arg(samp_rate.to_string())
            .arg("-m")
            .arg(mode.flag())
            .arg("-t")
            .arg(timeslot.to_string());
        if let Some(u) = subslot {
            c.arg("-u").arg(u.to_string());
        }
        if let Some(cipher) = cipher {
            c.arg("-e").arg(cipher.a5.to_string());
            c.arg("-k").arg(&cipher.kc);
        }
        // The patched decoder reads these to place GSMTAP where we listen.
        c.env("CELLCAP_GSMTAP_PORT", collector_port.to_string());
        c.env(
            "CELLCAP_GSMTAP_SERVERPORT",
            collector_port.wrapping_add(1).to_string(),
        );
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(if self.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        die_with_parent(&mut c);
        c.spawn()
            .with_context(|| format!("starting the decoder ({})", decoder.display()))
    }

    /// True if this device has a power-sweep tool cellcap can drive for its own
    /// scan. Other devices (UHD, SoapySDR) are scanned with grgsm_scanner.
    pub fn can_sweep(&self) -> bool {
        matches!(self.kind(), Kind::RtlSdr | Kind::HackRf)
    }

    /// Scan a whole band for cells with grgsm_scanner. This works over any
    /// gr-osmosdr device, including UHD, where there is no power-sweep tool.
    /// grgsm_scanner does the sweep, decode and cell identification itself.
    pub fn scan_cells(&self, band_name: &str, samp_rate: u64) -> Result<Vec<ScannedCell>> {
        let out = std::env::temp_dir().join(format!("cellcap-scan-{}.txt", std::process::id()));
        let file =
            std::fs::File::create(&out).with_context(|| format!("creating {}", out.display()))?;
        let mut c = Command::new("grgsm_scanner");
        c.arg("-b")
            .arg(band_name)
            .arg("--args")
            .arg(&self.device)
            .arg("-g")
            .arg(self.gain.to_string())
            .arg("-p")
            .arg(self.ppm.to_string())
            .arg("-s")
            .arg(samp_rate.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(if self.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        die_with_parent(&mut c);
        let mut child = c
            .spawn()
            .context("starting grgsm_scanner (is gr-gsm installed? Debian: apt install gr-gsm)")?;
        // A full band scan can take a few minutes.
        let deadline = Instant::now() + Duration::from_secs(600);
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() > deadline || crate::stopping() {
                stop(&mut child);
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::remove_file(&out);
        let cells = parse_scanner(&text);
        if cells.is_empty() && !status.success() && !crate::stopping() {
            bail!("grgsm_scanner found no cells and exited with {status}; re-run with --verbose-radio (is the SDR attached and free, and does it reach {band_name}?)");
        }
        Ok(cells)
    }

    /// Measure power across a frequency range with the SDR's own sweep tool.
    pub fn sweep(&self, low_hz: u64, high_hz: u64) -> Result<Vec<Power>> {
        let out = std::env::temp_dir().join(format!("cellcap-sweep-{}.csv", std::process::id()));
        let mut c = match self.kind() {
            Kind::RtlSdr => {
                let mut c = Command::new("rtl_power");
                c.arg("-f")
                    .arg(format!("{low_hz}:{high_hz}:25k"))
                    .arg("-g")
                    .arg(self.gain.to_string())
                    .arg("-p")
                    .arg(self.ppm.to_string())
                    .args(["-i", "4", "-1"]);
                if let Some(i) = self.index() {
                    c.arg("-d").arg(i);
                }
                c.arg(&out);
                c
            }
            Kind::HackRf => {
                // hackrf_sweep works in whole MHz and 20 MHz steps.
                let low = low_hz / 1_000_000;
                let span = (high_hz.div_ceil(1_000_000) - low).div_ceil(20) * 20;
                let mut c = Command::new("hackrf_sweep");
                c.arg("-f")
                    .arg(format!("{low}:{}", low + span))
                    .args(["-w", "25000", "-N", "8", "-r"])
                    .arg(&out);
                c
            }
            Kind::Other => bail!(
                "scanning needs an RTL-SDR (--device rtl=0) or a HackRF (--device hackrf=0); give --freq or --arfcn for '{}'",
                self.device
            ),
        };
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(if self.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        die_with_parent(&mut c);
        let program = c.get_program().to_string_lossy().into_owned();
        let mut child = c.spawn().with_context(|| format!("starting {program}"))?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() > deadline || crate::stopping() {
                stop(&mut child);
                let _ = std::fs::remove_file(&out);
                bail!("{program} did not finish");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let csv = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::remove_file(&out);
        let power = parse_sweep(&csv);
        if power.is_empty() {
            return Err(anyhow!(
                "{program} produced no measurements ({status}); is the SDR attached and free? Re-run with --verbose-radio"
            ));
        }
        Ok(power)
    }
}

/// Parse `rtl_power` / `hackrf_sweep` CSV: date, time, low Hz, high Hz, bin
/// width, sample count, then one dB value per bin.
pub fn parse_sweep(csv: &str) -> Vec<Power> {
    let mut out = Vec::new();
    for line in csv.lines() {
        let f: Vec<&str> = line.split(',').map(str::trim).collect();
        let (Some(low), Some(step)) = (
            f.get(2).and_then(|v| v.parse::<f64>().ok()),
            f.get(4).and_then(|v| v.parse::<f64>().ok()),
        ) else {
            continue;
        };
        for (i, v) in f.iter().skip(6).enumerate() {
            if let Ok(db) = v.parse::<f64>() {
                if db.is_finite() {
                    out.push((low + step * (i as f64 + 0.5), db));
                }
            }
        }
    }
    out
}

/// Names of the external tools cellcap drives, for the preflight check.
pub const LIVEMON: &str = "grgsm_livemon_headless";
pub const CAPTURE_TOOL: &str = "grgsm_capture";
pub const DECODER: &str = "cellcap-decode";

/// Find a program on PATH, returning its full path.
pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let p = dir.join(program);
        p.is_file().then_some(p)
    })
}

/// Locate the patched decoder cellcap uses for dedicated/ciphered channels.
/// It is generated from grgsm_decode at install time (see the Makefile),
/// because the packaged grgsm_decode is broken against current GNU Radio.
pub fn find_decoder() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("CELLCAP_DECODE") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "CELLCAP_DECODE points at {}, which is not a file",
            p.display()
        );
    }
    // Next to the cellcap binary, then the usual install path, then PATH.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(DECODER);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    let installed = PathBuf::from("/usr/local/bin").join(DECODER);
    if installed.is_file() {
        return Ok(installed);
    }
    which(DECODER).ok_or_else(|| {
        anyhow!(
            "the decoder '{DECODER}' was not found; run `make install` to generate it from \
             grgsm_decode, or set CELLCAP_DECODE to its path (needed only for the `decode` command)"
        )
    })
}

/// Make a child receive SIGTERM if this process dies, so a crash never
/// leaves a decoder holding the SDR.
fn die_with_parent(c: &mut Command) {
    // SAFETY: prctl is async-signal-safe and touches only the child.
    unsafe {
        c.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
}

/// Stop a child: ask politely, then insist.
pub fn stop(child: &mut Child) {
    // SAFETY: the pid belongs to a child we have not yet reaped.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sweep_rows() {
        let csv =
            "2026-11-26, 13:00:00, 925000000, 925100000, 25000.00, 10, -20.5, -19.0, 3.5, nan\n\
                   garbage line\n\
                   2026-11-26, 13:00:00, 925100000, 925200000, 25000.00, 10, -1.0\n";
        let p = parse_sweep(csv);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], (925_012_500.0, -20.5));
        assert_eq!(p[2], (925_062_500.0, 3.5));
        assert_eq!(p[3], (925_112_500.0, -1.0));
    }

    #[test]
    fn parses_grgsm_scanner_cells() {
        // The exact format grgsm_scanner prints (source line 558).
        let out = "Using avx for something\n\
            ARFCN:   11, Freq:  937.2M, CID:  1660, LAC:   431, MCC: 238, MNC:   1, Pwr: -34\n\
            Scanning: 50.00% done..\n\
            ARFCN: 1016, Freq:  959.8M, CID:  4660, LAC:   431, MCC: 238, MNC:  66, Pwr: -51\n";
        let cells = parse_scanner(out);
        assert_eq!(cells.len(), 2);
        assert_eq!(cells[0].arfcn, 11);
        assert_eq!(cells[0].freq_hz, 937_200_000);
        assert_eq!(cells[0].cid, 1660);
        assert_eq!(cells[0].lac, 431);
        assert_eq!((cells[0].mcc, cells[0].mnc), (238, 1));
        assert_eq!(cells[0].power_db, -34.0);
        assert_eq!(cells[1].arfcn, 1016);
        assert_eq!(cells[1].mnc, 66);
    }

    #[test]
    fn can_sweep_only_for_rtl_and_hackrf() {
        let r = |d: &str| Radio {
            device: d.into(),
            gain: 40.0,
            ppm: 0,
            port: 47290,
            verbose: false,
        };
        assert!(r("rtl=0").can_sweep());
        assert!(r("hackrf=0").can_sweep());
        assert!(!r("uhd").can_sweep());
        assert!(!r("soapy=0").can_sweep());
    }

    #[test]
    fn device_kind_and_index() {
        let r = |d: &str| Radio {
            device: d.into(),
            gain: 40.0,
            ppm: 0,
            port: 47290,
            verbose: false,
        };
        assert_eq!(r("rtl=1").kind(), Kind::RtlSdr);
        assert_eq!(r("rtl=1").index(), Some("1"));
        assert_eq!(r("hackrf=0").kind(), Kind::HackRf);
        assert_eq!(r("rtl=00001002").index(), Some("00001002"));
        assert_eq!(r("uhd").kind(), Kind::Other);
        assert_eq!(r("uhd").index(), None);
    }
}
