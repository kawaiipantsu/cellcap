//! `cellcap check`: a preflight checklist. It reports, with ticks and crosses,
//! whether the tools cellcap drives are installed and whether an SDR is
//! present, so missing pieces can be installed and the check re-run until
//! everything is OK.

use crate::radio;
use anyhow::Result;
use std::io::IsTerminal;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Ok,
    Missing,
    /// Not present, but only needed for part of cellcap.
    Optional,
}

struct Report {
    colour: bool,
    required_missing: u32,
}

impl Report {
    fn line(&mut self, state: State, name: &str, detail: &str) {
        if state == State::Missing {
            self.required_missing += 1;
        }
        let (glyph, colour) = match state {
            State::Ok => ("[OK]", GREEN),
            State::Missing => ("[ X]", RED),
            State::Optional => ("[ -]", YELLOW),
        };
        if self.colour {
            println!("  {colour}{glyph}{RESET}  {name:<26} {DIM}{detail}{RESET}");
        } else {
            println!("  {glyph}  {name:<26} {detail}");
        }
    }

    fn heading(&self, text: &str) {
        if self.colour {
            println!("\n\x1b[1m{text}\x1b[0m");
        } else {
            println!("\n{text}");
        }
    }
}

/// Run a command briefly and return its combined output and whether it exited
/// successfully, or None if it could not be started. Used to ask a tool or an
/// SDR whether it is there. A process still running at the timeout is killed
/// and reported as unsuccessful.
fn probe(program: &str, args: &[&str], secs: u64) -> Option<(String, bool)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut timed_out = false;
    loop {
        if child.try_wait().ok()?.is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some((s, out.status.success() && !timed_out))
}

/// Check one tool on PATH.
fn tool(r: &mut Report, program: &str, state_if_missing: State, detail: &str) {
    match radio::which(program) {
        Some(p) => r.line(State::Ok, program, &p.display().to_string()),
        None => r.line(state_if_missing, program, detail),
    }
}

pub fn run() -> Result<()> {
    let colour = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut r = Report {
        colour,
        required_missing: 0,
    };

    println!("cellcap {} preflight check", env!("CARGO_PKG_VERSION"));

    r.heading("Required for live capture (run / scan)");
    tool(
        &mut r,
        radio::LIVEMON,
        State::Missing,
        "install gr-gsm (Debian: apt install gr-gsm)",
    );
    tool(
        &mut r,
        "rtl_power",
        State::Optional,
        "RTL-SDR scanning (apt install rtl-sdr) — or use hackrf_sweep",
    );
    tool(
        &mut r,
        "hackrf_sweep",
        State::Optional,
        "HackRF scanning (apt install hackrf)",
    );

    r.heading("Required for decode / decrypt (decode)");
    tool(
        &mut r,
        radio::CAPTURE_TOOL,
        State::Optional,
        "recording cfiles (apt install gr-gsm)",
    );
    match radio::find_decoder() {
        Ok(p) => r.line(State::Ok, radio::DECODER, &p.display().to_string()),
        Err(_) => r.line(
            State::Optional,
            radio::DECODER,
            "not generated yet — run `make install` (patches grgsm_decode for this GNU Radio)",
        ),
    }

    r.heading("gr-gsm runtime");
    match probe("python3", &["-c", "from gnuradio import gsm, network"], 20) {
        Some((_, true)) => r.line(State::Ok, "gnuradio gsm + network", "importable"),
        Some((out, false)) => r.line(
            State::Missing,
            "gnuradio gsm + network",
            out.lines()
                .rev()
                .find(|l| l.contains("Error") || l.contains("error"))
                .unwrap_or("import failed"),
        ),
        None => r.line(State::Missing, "python3", "not found"),
    }

    r.heading("SDR device");
    let mut any_sdr = false;
    // RTL-SDR
    match probe("rtl_test", &["-t"], 3) {
        Some((out, _)) if out.contains("Found") && !out.contains("No supported devices") => {
            any_sdr = true;
            let name = out
                .lines()
                .find(|l| l.trim_start().starts_with('0'))
                .map(str::trim)
                .unwrap_or("present");
            r.line(State::Ok, "RTL-SDR (rtl=0)", name);
        }
        Some(_) => r.line(State::Optional, "RTL-SDR", "no RTL-SDR detected"),
        None => r.line(
            State::Optional,
            "RTL-SDR (rtl_test)",
            "rtl-sdr tools not installed",
        ),
    }
    // HackRF
    match probe("hackrf_info", &[], 3) {
        Some((out, _)) if out.contains("Serial number") || out.contains("Found HackRF") => {
            any_sdr = true;
            r.line(State::Ok, "HackRF (hackrf=0)", "present");
        }
        Some(_) => r.line(State::Optional, "HackRF", "no HackRF detected"),
        None => r.line(
            State::Optional,
            "HackRF (hackrf_info)",
            "hackrf tools not installed",
        ),
    }
    if !any_sdr {
        r.required_missing += 1;
        r.line(
            State::Missing,
            "an SDR",
            "no RTL-SDR or HackRF was detected",
        );
    }

    println!();
    if r.required_missing == 0 {
        let msg = "All required pieces are present — cellcap can capture.";
        if colour {
            println!("{GREEN}{msg}{RESET}");
        } else {
            println!("{msg}");
        }
    } else {
        let msg = format!(
            "{} required item(s) missing. Install them and run `cellcap check` again.",
            r.required_missing
        );
        if colour {
            println!("{RED}{msg}{RESET}");
        } else {
            println!("{msg}");
        }
        std::process::exit(1);
    }
    Ok(())
}
