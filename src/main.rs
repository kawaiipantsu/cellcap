//! cellcap: passive capture of cellular broadcast channels for Wireshark.
//!
//! It only listens. Today it handles GSM: a power sweep and a short decode
//! find the cells, gr-gsm demodulates the chosen channel, and the decoded
//! frames are written as pcapng.

mod atmodem;
mod capture;
mod check;
mod decode;
mod freq;
mod gsmtap;
mod inspect;
mod live;
mod lte;
mod model;
mod pcapng;
mod radio;
mod scan;
mod simaudit;
mod tui;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::IsTerminal;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// True once SIGINT or SIGTERM has been received.
pub fn stopping() -> bool {
    STOP.get().is_some_and(|s| s.load(Ordering::Relaxed))
}

/// Ask the capture loop to stop, as the TUI does when the operator quits.
pub fn request_stop() {
    if let Some(s) = STOP.get() {
        s.store(true, Ordering::Relaxed);
    }
}

/// The start-up banner with its colour codes removed, for the TUI.
pub fn banner_plain() -> String {
    banner(false)
}

#[derive(Parser)]
#[command(
    version,
    about = "Passive cellular capture for Wireshark: finds GSM cells, decodes their broadcast channels and writes pcapng files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find cells and print them; captures nothing
    Scan {
        #[command(flatten)]
        radio: RadioArgs,
        #[command(flatten)]
        scan: ScanArgs,
    },
    /// Summarise one or more capture files, like `tshark -z` (no radio needed)
    Inspect {
        /// The pcapng file(s) to read back and summarise
        #[arg(value_name = "FILE", required = true)]
        files: Vec<PathBuf>,
    },
    /// Check that the required tools and an SDR are present (a ✓/✗ checklist)
    Check,
    /// Read the SIM's current session key Kc from a serial GSM modem (AT+CRSM)
    ExtractKc {
        /// Serial device of the modem
        #[arg(value_name = "DEVICE", default_value = "/dev/ttyUSB0")]
        device: PathBuf,
        /// Serial baud rate
        #[arg(long, default_value_t = 115200, value_name = "BAUD")]
        baud: u32,
    },
    /// Read useful SIM files from a serial modem: IMSI, Kc, GPRS Kc, TMSI/LAI
    SimInfo {
        /// Serial device of the modem
        #[arg(value_name = "DEVICE", default_value = "/dev/ttyUSB0")]
        device: PathBuf,
        /// Serial baud rate
        #[arg(long, default_value_t = 115200, value_name = "BAUD")]
        baud: u32,
    },
    /// Audit the SIM for toolkit/OTA features behind known attacks (Simjacker, WIB)
    AuditSim {
        /// Serial device of the modem
        #[arg(value_name = "DEVICE", default_value = "/dev/ttyUSB0")]
        device: PathBuf,
        /// Serial baud rate
        #[arg(long, default_value_t = 115200, value_name = "BAUD")]
        baud: u32,
    },
    /// Capture the LTE (4G) downlink into a Wireshark MAC-LTE pcap (drives LTESniffer)
    Lte {
        /// Downlink centre frequency, e.g. 1842.5M
        #[arg(long = "freq", value_name = "FREQUENCY", value_parser = freq::parse_hz)]
        freq: Option<u64>,
        /// Downlink EARFCN instead of --freq (common FDD bands 1-66)
        #[arg(long, value_name = "EARFCN")]
        earfcn: Option<u32>,
        /// RX antennas: 1 (TM1) or 2 (2x2 MIMO). The B210 has two.
        #[arg(long, default_value_t = 2, value_name = "N")]
        antennas: u8,
        /// Decoder worker threads
        #[arg(long, default_value_t = 4, value_name = "N")]
        threads: u8,
        /// Fixed RX gain in dB (default: device AGC)
        #[arg(long, value_name = "DB")]
        gain: Option<f32>,
        /// UHD device arguments for LTESniffer's -a (the B210 needs the larger buffer)
        #[arg(
            long = "rf-args",
            default_value = "num_recv_frames=512",
            value_name = "ARGS"
        )]
        rf_args: String,
        /// Lock to this physical cell id instead of searching (needs --prb)
        #[arg(long = "cell-id", value_name = "PCI")]
        cell_id: Option<u16>,
        /// Cell bandwidth in resource blocks for a fixed cell: 6/15/25/50/75/100
        #[arg(long, value_name = "PRB")]
        prb: Option<u16>,
        /// Directory for the capture
        #[arg(long, default_value = "/var/lib/cellcap/captures", value_name = "DIR")]
        output_dir: PathBuf,
        /// Show LTESniffer's own output
        #[arg(long)]
        verbose: bool,
    },
    /// Decode a dedicated or ciphered channel (SDCCH, TCH) into a pcapng
    Decode {
        #[command(flatten)]
        radio: RadioArgs,
        /// Downlink frequency of the cell, e.g. 937.2M (for recording and decoding)
        #[arg(long = "freq", value_name = "FREQUENCY", value_parser = freq::parse_hz)]
        freq: Option<u64>,
        /// Channel number instead of --freq
        #[arg(long = "arfcn", value_name = "ARFCN")]
        arfcn: Option<u16>,
        /// Which channel to decode
        #[arg(long, value_enum, default_value_t = DecodeModeArg::Sdcch8)]
        mode: DecodeModeArg,
        /// Timeslot to decode (0-7)
        #[arg(long, default_value_t = 1, value_name = "N")]
        timeslot: u8,
        /// Subslot, for BCCH_SDCCH4 / SDCCH8
        #[arg(long, value_name = "N")]
        subslot: Option<u8>,
        /// A5 cipher version (1, 2 or 3); needed with --cipher-kc for a ciphered channel
        #[arg(long = "cipher-a5", value_name = "N")]
        cipher_a5: Option<u8>,
        /// Session key Kc, e.g. 1234567890ABCDEF — decrypts the channel in the decoder
        #[arg(long = "cipher-kc", value_name = "HEX")]
        cipher_kc: Option<String>,
        /// SIM master key Ki — not usable directly (cellcap cannot derive Kc from it; see note)
        #[arg(long = "cipher-ki", value_name = "HEX")]
        cipher_ki: Option<String>,
        /// Decode this cfile instead of recording from the SDR
        #[arg(long, value_name = "FILE")]
        cfile: Option<PathBuf>,
        /// Seconds to record when not given a --cfile
        #[arg(long, default_value_t = 20, value_name = "SECONDS")]
        record_seconds: u64,
        /// Sample rate for recording and decoding
        #[arg(long, default_value_t = 1_000_000, value_name = "HZ")]
        samp_rate: u64,
        /// Keep the recorded cfile instead of deleting it
        #[arg(long)]
        keep_cfile: bool,
        /// Directory for the capture (and any kept cfile)
        #[arg(long, default_value = "/var/lib/cellcap/captures", value_name = "DIR")]
        output_dir: PathBuf,
    },
    /// Capture to pcapng files until stopped (this is what the service runs)
    Run {
        #[command(flatten)]
        radio: RadioArgs,
        #[command(flatten)]
        scan: ScanArgs,
        /// Downlink frequency to capture, e.g. 937.2M. Repeat to cycle through several.
        /// Without --freq or --arfcn, cellcap scans and picks the strongest cell.
        #[arg(long = "freq", value_name = "FREQUENCY", value_parser = freq::parse_hz)]
        freqs: Vec<u64>,
        /// Channel number to capture, as an alternative to --freq. Repeatable.
        #[arg(long = "arfcn", value_name = "ARFCN")]
        arfcns: Vec<u16>,
        /// After a scan, capture this many of the cells found
        #[arg(long, default_value_t = 1, value_name = "COUNT")]
        cells: usize,
        /// After a scan, only pick cells of this network: MCC then MNC, e.g. 23801
        #[arg(long, value_name = "MCCMNC")]
        plmn: Option<String>,
        /// Seconds on each channel when capturing several
        #[arg(long, default_value_t = 120, value_name = "SECONDS")]
        dwell: u64,
        /// Restart the decoder when no frame arrives for this many seconds
        #[arg(long, default_value_t = 45, value_name = "SECONDS")]
        stall_seconds: u64,
        /// Directory for the capture files
        #[arg(long, default_value = "/var/lib/cellcap/captures", value_name = "DIR")]
        output_dir: PathBuf,
        /// Start a new file after this many minutes
        #[arg(long, default_value_t = 60, value_name = "MINUTES")]
        rotate_minutes: u64,
        /// Start a new file after this many megabytes
        #[arg(long, default_value_t = 50, value_name = "MB")]
        rotate_mb: u64,
        /// Delete the oldest captures when the directory exceeds this many megabytes
        #[arg(long, default_value_t = 2000, value_name = "MB")]
        max_total_mb: u64,
        /// Show a live terminal dashboard (tabs: overview, live, cells, captures, log)
        #[arg(short, long)]
        interactive: bool,
        /// Print one readable line per message to stdout instead of the dashboard
        #[arg(long)]
        stream: bool,
        /// Do not write capture files (to just watch with --interactive or --stream)
        #[arg(long)]
        no_write: bool,
        /// Leave paging messages out of the capture. They carry the temporary
        /// or permanent identities of other subscribers.
        #[arg(long)]
        drop_paging: bool,
    },
}

#[derive(Args)]
struct RadioArgs {
    /// SDR to use, as gr-osmosdr device arguments: rtl=0, hackrf=0, ...
    #[arg(long, default_value = "rtl=0", value_name = "ARGS")]
    device: String,
    /// RF gain in dB
    #[arg(long, default_value_t = 40.0, value_name = "DB")]
    gain: f32,
    /// Frequency correction in parts per million
    #[arg(
        long,
        default_value_t = 0,
        allow_hyphen_values = true,
        value_name = "PPM"
    )]
    ppm: i32,
    /// Local UDP port the decoder delivers frames to (the decoder also uses the next port up)
    #[arg(long, default_value_t = 47290, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1024..65535))]
    port: u16,
    /// Show the output of the radio tools (gr-gsm, rtl_power, hackrf_sweep)
    #[arg(long)]
    verbose_radio: bool,
}

#[derive(Args)]
struct ScanArgs {
    /// Band to scan: GSM900, DCS1800 or GSM850. Repeatable.
    #[arg(long = "band", default_value = "GSM900", value_name = "BAND", value_parser = freq::Band::parse)]
    bands: Vec<freq::Band>,
    /// Probe this many of the strongest channels per band
    #[arg(long = "scan-top", default_value_t = 8, value_name = "COUNT")]
    top: usize,
    /// Seconds to listen on each channel while probing
    #[arg(long, default_value_t = 15, value_name = "SECONDS")]
    probe_seconds: u64,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum DecodeModeArg {
    Bcch,
    #[value(name = "bcch-sdcch4")]
    BcchSdcch4,
    Sdcch8,
    Tchf,
    Tchh,
}

impl From<DecodeModeArg> for radio::DecodeMode {
    fn from(m: DecodeModeArg) -> Self {
        match m {
            DecodeModeArg::Bcch => radio::DecodeMode::Bcch,
            DecodeModeArg::BcchSdcch4 => radio::DecodeMode::BcchSdcch4,
            DecodeModeArg::Sdcch8 => radio::DecodeMode::Sdcch8,
            DecodeModeArg::Tchf => radio::DecodeMode::Tchf,
            DecodeModeArg::Tchh => radio::DecodeMode::Tchh,
        }
    }
}

impl RadioArgs {
    fn radio(&self) -> radio::Radio {
        radio::Radio {
            device: self.device.clone(),
            gain: self.gain,
            ppm: self.ppm,
            port: self.port,
            verbose: self.verbose_radio,
        }
    }
}

/// The start-up banner, with its colour codes removed when `color` is false.
fn banner(color: bool) -> String {
    let art = include_str!("banner.txt")
        .trim_end()
        .replace("{version}", env!("CARGO_PKG_VERSION"));
    if color {
        return art;
    }
    let mut plain = String::with_capacity(art.len());
    let mut chars = art.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip the escape sequence up to and including its final letter.
            for e in chars.by_ref() {
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

fn socket(port: u16) -> Result<UdpSocket> {
    let s = UdpSocket::bind(("127.0.0.1", port)).with_context(|| {
        format!("binding UDP 127.0.0.1:{port} (is another cellcap or GSMTAP listener running? choose another with --port)")
    })?;
    s.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(s)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, stop.clone())?;
    }
    let _ = STOP.set(stop);

    match cli.command {
        Command::Scan { radio, scan } => {
            let r = radio.radio();
            let s = socket(r.port)?;
            let found = scan::scan(&r, &s, &scan.bands, scan.top, scan.probe_seconds)?;
            if found.is_empty() {
                bail!("nothing found: no channel stands out in the scanned band(s)");
            }
            print!("{}", scan::table(&found));
        }
        Command::Inspect { files } => {
            for (i, file) in files.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print!("{}", inspect::report(file)?);
            }
        }
        Command::Check => check::run()?,
        Command::ExtractKc { device, baud } => {
            let kc = atmodem::read_kc(&device, baud)?;
            println!("Kc    {}", kc.kc_hex);
            println!("CKSN  {}", kc.sequence);
            eprintln!(
                "info: decipher a channel with: cellcap decode --freq <F> --arfcn <N> \
                 --mode sdcch8 --timeslot <T> --cipher-a5 1 --cipher-kc {}",
                kc.kc_hex
            );
        }
        Command::SimInfo { device, baud } => {
            let info = atmodem::read_sim_info(&device, baud)?;
            if let Some(imsi) = &info.imsi {
                println!("IMSI        {imsi}");
            }
            if let Some(l) = &info.loci {
                println!("TMSI        {}", l.tmsi);
                println!("LAI         MCC {} MNC {} LAC {}", l.mcc, l.mnc, l.lac);
                println!("Registered  {}", l.status);
            }
            if let Some(kc) = &info.kc {
                println!("Kc          {}  (CKSN {})", kc.kc_hex, kc.sequence);
            }
            if let Some(kc) = &info.kc_gprs {
                println!("Kc (GPRS)   {}  (seq {})", kc.kc_hex, kc.sequence);
            }
            if info.kc.is_none() {
                eprintln!(
                    "info: no GSM Kc stored yet — force a 2G authentication, then read again"
                );
            }
        }
        Command::AuditSim { device, baud } => simaudit::run(&device, baud)?,
        Command::Lte {
            freq,
            earfcn,
            antennas,
            threads,
            gain,
            rf_args,
            cell_id,
            prb,
            output_dir,
            verbose,
        } => {
            let freq_hz = match (freq, earfcn) {
                (Some(f), _) => f,
                (None, Some(e)) => lte::earfcn_to_hz(e).ok_or_else(|| {
                    anyhow!("EARFCN {e} is not in the FDD bands cellcap knows; pass --freq instead")
                })?,
                (None, None) => {
                    bail!("give --freq (e.g. 1842.5M) or --earfcn for the LTE downlink")
                }
            };
            if cell_id.is_some() != prb.is_some() {
                bail!("--cell-id and --prb go together: a fixed cell needs both, or give neither to search");
            }
            let job = lte::Job {
                freq_hz,
                antennas,
                threads,
                gain,
                rf_args,
                cell_search: cell_id.is_none(),
                cell_id,
                prb,
                output_dir,
                verbose,
            };
            lte::run(&job)?;
        }
        Command::Decode {
            radio,
            freq,
            arfcn,
            mode,
            timeslot,
            subslot,
            cipher_a5,
            cipher_kc,
            cipher_ki,
            cfile,
            record_seconds,
            samp_rate,
            keep_cfile,
            output_dir,
        } => {
            if cipher_ki.is_some() {
                bail!(
                    "--cipher-ki cannot be used directly: Ki is the SIM master key, not the A5 \
                     session key. Derive the per-session Kc from Ki and the RAND in the \
                     Authentication Request (e.g. with osmo-sim-auth), or read Kc from the test \
                     phone, then pass it with --cipher-kc."
                );
            }
            let cipher = match (cipher_kc, cipher_a5) {
                (Some(kc), a5) => Some(radio::Cipher {
                    a5: a5.unwrap_or(1),
                    kc,
                }),
                (None, Some(_)) => bail!("--cipher-a5 needs --cipher-kc (the session key)"),
                (None, None) => None,
            };
            let hz = match (freq, arfcn) {
                (Some(f), _) => f,
                (None, Some(a)) => freq::arfcn_to_hz(a)
                    .with_context(|| format!("ARFCN {a} is not in a known band"))?,
                (None, None) => {
                    bail!("decode needs the cell frequency: give --freq or --arfcn")
                }
            };
            let r = radio.radio();
            let s = socket(r.port)?;
            let limits = pcapng::Limits {
                rotate_after: Duration::from_secs(3600),
                rotate_bytes: 200 * 1024 * 1024,
                max_total_bytes: 4000 * 1024 * 1024,
            };
            let m: radio::DecodeMode = mode.into();
            let description = format!(
                "GSM {} timeslot {timeslot} decoded by gr-gsm{}",
                m.flag(),
                if cipher.is_some() {
                    " (deciphered)"
                } else {
                    ""
                }
            );
            let mut writer = pcapng::Writer::new(&output_dir, limits, description)?;
            let job = decode::Job {
                hz,
                mode: m,
                timeslot,
                subslot,
                cipher,
                cfile,
                record_seconds,
                samp_rate,
                keep_cfile,
            };
            decode::run(&r, &s, &mut writer, &job, &output_dir)?;
            writer.close()?;
        }
        Command::Run {
            radio,
            scan,
            freqs,
            arfcns,
            cells,
            plmn,
            dwell,
            stall_seconds,
            output_dir,
            rotate_minutes,
            rotate_mb,
            max_total_mb,
            drop_paging,
            interactive,
            stream,
            no_write,
        } => {
            if no_write && !(interactive || stream) {
                bail!("--no-write without --interactive or --stream would capture nothing and show nothing");
            }
            if interactive && stream {
                bail!("--interactive and --stream are two ways to watch; choose one");
            }
            if interactive && !std::io::stdout().is_terminal() {
                bail!("--interactive needs a terminal; use --stream for a plain view, or neither to run headless");
            }
            let colour = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
            let mut targets = freqs;
            for a in arfcns {
                targets.push(freq::arfcn_to_hz(a).with_context(|| {
                    format!("ARFCN {a} is not in GSM 850, GSM 900 or DCS 1800")
                })?);
            }
            targets.dedup();
            let r = radio.radio();
            let s = socket(r.port)?;
            let limits = pcapng::Limits {
                rotate_after: Duration::from_secs(rotate_minutes.max(1) * 60),
                rotate_bytes: rotate_mb.max(1) * 1024 * 1024,
                max_total_bytes: max_total_mb.max(1) * 1024 * 1024,
            };
            let description = format!(
                "GSM broadcast and common control channels received with {} and decoded by gr-gsm",
                r.device
            );
            let mut writer = match no_write {
                true => None,
                false => Some(pcapng::Writer::new(&output_dir, limits, description)?),
            };
            let output = (!no_write).then(|| output_dir.display().to_string());
            let options = capture::Options {
                targets,
                bands: scan.bands,
                cells,
                plmn,
                scan_top: scan.top,
                probe_seconds: scan.probe_seconds,
                dwell: Duration::from_secs(dwell.max(10)),
                stall: Duration::from_secs(stall_seconds.max(10)),
                drop_paging,
            };
            if interactive {
                let model = Arc::new(model::Model::new(r.device.clone(), output));
                run_tui(r, s, writer, options, model)?;
            } else {
                eprintln!(
                    "info: cellcap {} starting; device {}, output {}",
                    env!("CARGO_PKG_VERSION"),
                    r.device,
                    output.unwrap_or_else(|| "none (--no-write)".into())
                );
                let rep = if stream {
                    capture::Reporter::Stream(live::Live::new(colour))
                } else {
                    capture::Reporter::Headless
                };
                capture::run(&r, &s, writer.as_mut(), rep, &options)?;
            }
        }
    }
    Ok(())
}

/// Run the capture loop on a worker thread and the dashboard on this one.
fn run_tui(
    r: radio::Radio,
    s: UdpSocket,
    writer: Option<pcapng::Writer>,
    options: capture::Options,
    model: Arc<model::Model>,
) -> Result<()> {
    // Everything the capture loop would print to stderr (the scan, the writer)
    // is routed into the dashboard's log instead of over the screen.
    let _stderr = tui::capture_stderr(model.clone());
    let finished = Arc::new(AtomicBool::new(false));
    let err: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let (done, err_slot, feed) = (finished.clone(), err.clone(), model.clone());
    let worker = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            let mut writer = writer;
            let res = capture::run(
                &r,
                &s,
                writer.as_mut(),
                capture::Reporter::Tui(feed),
                &options,
            );
            if let Err(e) = &res {
                *err_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("{e:#}"));
            }
            done.store(true, Ordering::Relaxed);
        })?;
    let drawn = tui::run(model, finished);
    // The dashboard asked the loop to stop on its way out; wait for it.
    let _ = worker.join();
    drawn?;
    if let Some(e) = err.lock().unwrap_or_else(|e| e.into_inner()).take() {
        bail!(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_without_colour_has_no_escape_codes() {
        assert!(banner(true).contains('\x1b'));
        let plain = banner(false);
        assert!(!plain.contains('\x1b') && !plain.contains("[0m"));
        assert!(plain.contains(concat!("cellcap ", env!("CARGO_PKG_VERSION"))));
        // Every line of the lower box is the same width.
        let widths: Vec<usize> = plain
            .lines()
            .filter(|l| ["   ║ ", "   ╔═", "   ╚═"].iter().any(|p| l.starts_with(p)))
            .map(|l| l.chars().count())
            .collect();
        assert!(widths.len() >= 8 && widths.iter().all(|w| *w == widths[0]));
    }
}
