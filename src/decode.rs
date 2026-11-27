//! Decode a dedicated or ciphered channel: record a short cfile (or take one
//! given), run the decoder over it, and write the GSMTAP it produces to a
//! pcapng. Unlike the live capture, this is a one-shot — it ends when the
//! decoder reaches the end of the file.
//!
//! Decryption, when a key is given, happens inside the decoder (A5/Kc); the
//! frames reach Wireshark already in the clear.

use crate::gsmtap::{self, Kind};
use crate::pcapng::{self, Writer};
use crate::radio::{Cipher, DecodeMode, Radio};
use crate::scan;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Job {
    pub hz: u64,
    pub mode: DecodeMode,
    pub timeslot: u8,
    pub subslot: Option<u8>,
    pub cipher: Option<Cipher>,
    /// Decode this cfile instead of recording one.
    pub cfile: Option<PathBuf>,
    pub record_seconds: u64,
    pub samp_rate: u64,
    /// Keep the recorded cfile instead of deleting it afterwards.
    pub keep_cfile: bool,
}

/// Record (or reuse) a cfile and decode it into `writer`.
pub fn run(
    radio: &Radio,
    socket: &UdpSocket,
    writer: &mut Writer,
    job: &Job,
    dir: &std::path::Path,
) -> Result<()> {
    // Obtain the samples: a given file, or a fresh recording.
    let (cfile, recorded) = match &job.cfile {
        Some(p) => {
            if !p.is_file() {
                bail!("cfile {} does not exist", p.display());
            }
            (p.clone(), false)
        }
        None => {
            let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
            let path = dir.join(format!("cellcap-record-{stamp}.cfile"));
            eprintln!(
                "info: recording {} s on {} to {}",
                job.record_seconds,
                crate::freq::mhz(job.hz),
                path.display()
            );
            radio
                .record(job.hz, job.record_seconds, job.samp_rate, &path)
                .context("recording the cfile")?;
            (path, true)
        }
    };

    let result = decode_file(radio, socket, writer, job, &cfile);

    if recorded && !job.keep_cfile {
        let _ = std::fs::remove_file(&cfile);
    } else if recorded {
        eprintln!("info: kept recording {}", cfile.display());
    }
    result
}

fn decode_file(
    radio: &Radio,
    socket: &UdpSocket,
    writer: &mut Writer,
    job: &Job,
    cfile: &std::path::Path,
) -> Result<()> {
    let port = socket.local_addr()?.port();
    scan::drain(socket);
    eprintln!(
        "info: decoding {} as {} timeslot {}{}{}",
        cfile.display(),
        job.mode.flag(),
        job.timeslot,
        job.subslot
            .map(|u| format!(" subslot {u}"))
            .unwrap_or_default(),
        if job.cipher.is_some() {
            " (deciphering with the given A5/Kc)"
        } else {
            ""
        }
    );
    let mut child = radio.decode(
        cfile,
        job.hz,
        job.samp_rate,
        job.mode,
        job.timeslot,
        job.subslot,
        job.cipher.as_ref(),
        port,
    )?;

    // grgsm_decode leaves the GSMTAP ARFCN field at 0 when decoding a cfile.
    // We know which channel this is, so stamp it in (downlink, no flags) for
    // Wireshark's ARFCN column.
    let arfcn = crate::freq::hz_to_arfcn(job.hz);
    let mut buf = [0u8; 2048];
    let mut written = 0u64;
    let mut by_channel: BTreeMap<u8, u64> = BTreeMap::new();
    let mut by_kind: BTreeMap<&'static str, u64> = BTreeMap::new();
    // Keep draining for a moment after the decoder exits: its last frames may
    // still be in flight.
    let mut done_at: Option<Instant> = None;
    loop {
        if crate::stopping() {
            crate::radio::stop(&mut child);
            break;
        }
        if done_at.is_none() {
            if let Ok(Some(status)) = child.try_wait() {
                if !status.success() {
                    bail!(
                        "the decoder failed ({status}); re-run with --verbose-radio. \
                         If it reports a missing gnuradio attribute, regenerate it with `make install`."
                    );
                }
                done_at = Some(Instant::now());
            }
        }
        if let Some(t) = done_at {
            if t.elapsed() >= Duration::from_millis(800) {
                break;
            }
        }
        let Ok(n) = socket.recv(&mut buf) else {
            continue;
        };
        let Some(header) = gsmtap::header(&buf[..n]) else {
            continue;
        };
        // Fill in the ARFCN if the decoder left it blank.
        if header.arfcn == 0 {
            if let Some(a) = arfcn {
                buf[4..6].copy_from_slice(&a.to_be_bytes());
            }
        }
        let frame = &buf[..n];
        *by_channel.entry(header.channel).or_default() += 1;
        let kind = match gsmtap::kind(frame) {
            Kind::SystemInfo(_) => "system information",
            Kind::Paging => "paging",
            Kind::ImmediateAssignment => "immediate assignment",
            Kind::Other => "other (signalling / traffic)",
        };
        *by_kind.entry(kind).or_default() += 1;
        writer.write(pcapng::now_micros(), frame)?;
        written += 1;
    }
    writer.flush()?;

    if written == 0 {
        eprintln!(
            "info: no frames decoded. The channel may have been idle during the recording, \
             or (for a ciphered channel) the A5/Kc may not match."
        );
    } else {
        eprintln!("info: wrote {written} frame(s):");
        for (ch, n) in &by_channel {
            eprintln!("info:   {} {n}", crate::inspect::channel_name(*ch));
        }
        for (k, n) in &by_kind {
            eprintln!("info:   {k}: {n}");
        }
    }
    Ok(())
}
