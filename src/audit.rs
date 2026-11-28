//! `cellcap audit-cell`: camp on one cell for a while, then score whether it
//! behaves like a legitimate cell or a rogue / IMSI-catcher / sniffing /
//! misconfigured one. Passive only — it never transmits.
//!
//! The audit collects broadcast and dedicated-channel signalling for a fixed
//! window, then runs a checklist across five areas (identity exposure,
//! encryption, authentication, network identity, registration behaviour) and
//! prints a ✓/✗/⚠ report with a final confidence score. The checks are
//! heuristics on passively observed behaviour, not proof; the report says so.

use crate::freq;
use crate::gsmtap::{self, Kind};
use crate::history::{self, History};
use crate::radio::{self, Radio};
use crate::scan;
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::IsTerminal;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A cell found in the pre-audit scan, for neighbourhood comparison.
struct Neighbour {
    mcc: String,
    mnc: String,
    arfcn: u16,
    lac: u16,
    cid: u16,
    power_db: f64,
}

impl Neighbour {
    fn from_found(f: &scan::Found) -> Option<Self> {
        let c = f.cell.as_ref()?;
        Some(Neighbour {
            mcc: c.mcc.clone(),
            mnc: c.mnc.clone(),
            arfcn: f.candidate.arfcn,
            lac: c.lac,
            cid: c.cid,
            power_db: f.candidate.power_db,
        })
    }
    fn key(&self) -> String {
        history::key(&self.mcc, &self.mnc, self.arfcn, self.lac, self.cid)
    }
}

/// Context from the pre-scan and the on-disk history, for the extra checks.
#[derive(Default)]
struct Context {
    neighbours: Vec<Neighbour>,
    /// The target cell's prior record, if it has been seen before.
    target_known: Option<history::Seen>,
    /// Whether a non-empty history existed (so "new" is meaningful).
    had_baseline: bool,
    new_cells: usize,
    known_cells: usize,
}

/// Options for one cell audit.
pub struct Opts {
    pub seconds: u64,
    pub bands: Vec<crate::freq::Band>,
    pub scan_top: usize,
    pub probe_seconds: u64,
    pub scan: bool,
    pub history: Option<PathBuf>,
    /// Save the collected frames to a pcapng here, for evidence and to validate
    /// or extend the SI parsing offline.
    pub output_dir: Option<PathBuf>,
}

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// What was seen on the cell during the collection window.
#[derive(Default)]
struct Observations {
    frames: u64,
    arfcn: u16,
    cell: Option<gsmtap::Cell>,
    si_types: BTreeSet<u8>,
    a5_seen: BTreeSet<u8>,
    cipher_cmds: u32,
    auth_requests: u32,
    identity_requests: u32,
    identity_imsi_requests: u32,
    lu_requests: u32,
    lu_accepts: u32,
    lu_rejects: u32,
    reject_causes: BTreeMap<u8, u32>,
    /// Home network (MCC, MNC) of each subscriber seen attaching, with a count.
    home_plmns: BTreeMap<(String, String), u32>,
    paging_clear_imsi: u32,
    /// SI3 access parameters, once an SI3 has been decoded.
    si3: Option<gsmtap::Si3Params>,
    signal_sum: i64,
    signal_n: u64,
}

impl Observations {
    fn note(&mut self, frame: &[u8]) {
        let Some(header) = gsmtap::header(frame) else {
            return;
        };
        self.frames += 1;
        self.arfcn = header.arfcn;
        self.signal_sum += header.signal_dbm as i64;
        self.signal_n += 1;
        match gsmtap::kind(frame) {
            Kind::SystemInfo(t) => {
                self.si_types.insert(t);
                if let Some(c) = gsmtap::cell(frame) {
                    self.cell = Some(c);
                }
                if let Some(p) = gsmtap::si3_params(frame) {
                    self.si3 = Some(p);
                }
            }
            Kind::Paging => {
                if gsmtap::paged(frame).contains(&"IMSI") {
                    self.paging_clear_imsi += 1;
                }
            }
            Kind::ImmediateAssignment => {}
            Kind::Other => {
                if let Some((pd, mt, l3)) = gsmtap::l3_dedicated(frame) {
                    self.note_dtap(pd, mt, l3);
                }
            }
        }
    }

    fn note_dtap(&mut self, pd: u8, mt: u8, l3: &[u8]) {
        match (pd, mt) {
            (0x05, 0x08) => {
                self.lu_requests += 1;
                // Mobile Identity is an LV at l3[9] (pd, mt, cipher/LU type, LAI[5],
                // classmark1, then length + identity). Its IMSI names the home PLMN.
                if let Some((mcc, mnc)) = l3
                    .get(9)
                    .map(|&len| 10usize + len as usize)
                    .and_then(|end| l3.get(10..end))
                    .and_then(imsi_home_plmn)
                {
                    *self.home_plmns.entry((mcc, mnc)).or_default() += 1;
                }
            }
            (0x05, 0x02) => self.lu_accepts += 1,
            (0x05, 0x04) => {
                self.lu_rejects += 1;
                if let Some(c) = l3.get(2) {
                    *self.reject_causes.entry(*c).or_default() += 1;
                }
            }
            (0x05, 0x12) => self.auth_requests += 1,
            (0x05, 0x18) => {
                self.identity_requests += 1;
                // l3[2] low 3 bits: 1 = IMSI, 2 = IMEI (an identification demand).
                if matches!(l3.get(2).map(|o| o & 0x07), Some(1 | 2)) {
                    self.identity_imsi_requests += 1;
                }
            }
            // Ciphering Mode Command: octet 3 bit0 = start/stop, bits1-3 = algo.
            (0x06, 0x35) => {
                self.cipher_cmds += 1;
                if let Some(o) = l3.get(2) {
                    let a5 = if o & 0x01 == 0 {
                        0
                    } else {
                        ((o >> 1) & 0x07) + 1
                    };
                    self.a5_seen.insert(a5);
                }
            }
            _ => {}
        }
    }

    fn avg_signal(&self) -> i64 {
        if self.signal_n == 0 {
            0
        } else {
            self.signal_sum / self.signal_n as i64
        }
    }
}

/// Home PLMN (MCC, MNC) from the IMSI in a Mobile Identity element. Assumes a
/// two-digit MNC (correct for Denmark and most of Europe); it is a heuristic for
/// grouping, not an exact MNC-length decode. Returns None for a non-IMSI identity.
fn imsi_home_plmn(id: &[u8]) -> Option<(String, String)> {
    let first = *id.first()?;
    if first & 0x07 != 1 {
        return None; // not an IMSI (e.g. TMSI/IMEI)
    }
    let mut digits = vec![(first >> 4) & 0x0F];
    for &b in &id[1..] {
        digits.push(b & 0x0F);
        digits.push((b >> 4) & 0x0F);
    }
    if digits.len() < 5 || digits[..5].iter().any(|&n| n > 9) {
        return None;
    }
    let s = |r: std::ops::Range<usize>| digits[r].iter().map(|n| (b'0' + n) as char).collect();
    Some((s(0..3), s(3..5)))
}

/// Collect signalling on `hz` for `seconds`, printing brief progress. When a
/// `writer` is given, every decoded frame is also saved for evidence.
fn collect(
    radio: &Radio,
    socket: &UdpSocket,
    hz: u64,
    seconds: u64,
    mut writer: Option<&mut crate::pcapng::Writer>,
) -> Result<Observations> {
    const STALL: Duration = Duration::from_secs(18);
    let mut obs = Observations::default();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    // Drain anything the pre-scan's decoders left in the socket before starting.
    scan::drain(socket);
    let mut child = radio.decoder(hz)?;
    let mut buf = [0u8; 2048];
    let mut next_tick = Instant::now() + Duration::from_secs(15);
    let mut last_frame = Instant::now();
    while Instant::now() < deadline && !crate::stopping() {
        // Restart the decoder if it dies, or if it goes silent (it can come up
        // wedged when the SDR was still busy from the pre-scan — reopening fixes it).
        let dead = matches!(child.try_wait(), Ok(Some(_)));
        if dead || last_frame.elapsed() >= STALL {
            radio::stop(&mut child);
            scan::drain(socket);
            child = radio.decoder(hz)?;
            last_frame = Instant::now();
        }
        if let Ok(n) = socket.recv(&mut buf) {
            let frame = &buf[..n];
            obs.note(frame);
            if let Some(w) = writer.as_deref_mut() {
                w.write(crate::pcapng::now_micros(), frame)?;
            }
            last_frame = Instant::now();
        }
        if Instant::now() >= next_tick {
            let left = deadline.saturating_duration_since(Instant::now()).as_secs();
            eprintln!(
                "  … {} frames, {} registration(s); {}s left",
                obs.frames, obs.lu_requests, left
            );
            next_tick = Instant::now() + Duration::from_secs(15);
        }
    }
    radio::stop(&mut child);
    Ok(obs)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Pass,
    Warn,
    Fail,
    Info,
}

struct Check {
    mark: Mark,
    name: String,
    detail: String,
}

/// The scored result of an audit: the checklist, the penalty total, and which
/// threat/operational areas tripped.
struct Scored {
    sections: Vec<(&'static str, Vec<Check>)>,
    penalty: u32,
    flags: BTreeSet<&'static str>,
}

/// Turn observations into a scored checklist.
fn evaluate(o: &Observations, ctx: &Context) -> Scored {
    let mut penalty = 0u32;
    let mut flags: BTreeSet<&'static str> = BTreeSet::new();
    let mut add = |mark: Mark, flag: &'static str, cost: u32| {
        if mark == Mark::Fail || mark == Mark::Warn {
            penalty += cost;
            if !flag.is_empty() {
                flags.insert(flag);
            }
        }
    };

    // --- Identity exposure (tracking / IMSI catching) ---
    let imsi_req = {
        let (mark, detail) = match o.identity_imsi_requests {
            0 => (Mark::Pass, "none seen".into()),
            n @ 1..=2 => (Mark::Warn, format!("{n} IMSI/IMEI identity request(s)")),
            n => (
                Mark::Fail,
                format!("{n} IMSI/IMEI identity requests (forced identification)"),
            ),
        };
        add(
            mark,
            "catching",
            if o.identity_imsi_requests > 2 { 30 } else { 15 },
        );
        Check {
            mark,
            name: "No forced IMSI/IMEI identification".into(),
            detail,
        }
    };
    let clear_imsi = {
        let (mark, detail) = if o.paging_clear_imsi == 0 {
            (Mark::Pass, "none".into())
        } else {
            (
                Mark::Fail,
                format!(
                    "{} paging message(s) named an IMSI in the clear",
                    o.paging_clear_imsi
                ),
            )
        };
        add(mark, "exposure", 20);
        Check {
            mark,
            name: "No permanent identity (IMSI) in paging".into(),
            detail,
        }
    };

    // --- Encryption (sniffing) ---
    let has_a5_0 = o.a5_seen.contains(&0);
    let ciphering = {
        let (mark, detail) = if o.cipher_cmds == 0 {
            (Mark::Info, "not observed in this window".into())
        } else if has_a5_0 {
            (Mark::Fail, "A5/0 — traffic sent with NO encryption".into())
        } else {
            (
                Mark::Pass,
                format!("ciphered ({} command(s))", o.cipher_cmds),
            )
        };
        add(mark, "sniffing", 35);
        Check {
            mark,
            name: "Traffic is encrypted (not A5/0)".into(),
            detail,
        }
    };
    let strength = {
        let algos: Vec<String> = o.a5_seen.iter().map(|a| format!("A5/{a}")).collect();
        let (mark, detail) = if o.a5_seen.contains(&3) {
            (Mark::Pass, format!("{} — strong", algos.join(", ")))
        } else if o.a5_seen.contains(&1) || o.a5_seen.contains(&2) {
            (
                Mark::Warn,
                format!("{} — weak (breakable)", algos.join(", ")),
            )
        } else if has_a5_0 {
            (Mark::Fail, "A5/0 only".into())
        } else {
            (Mark::Info, "no cipher mode observed".into())
        };
        add(mark, "sniffing", 8);
        Check {
            mark,
            name: "Strong cipher offered (A5/3)".into(),
            detail,
        }
    };

    // --- Authentication ---
    let auth = {
        // Accepting a registration without a challenge is the real tell (a catcher
        // can't authenticate). Rejecting before auth, or no accepts at all, is not
        // suspicious — a reject (e.g. a test cell) comes before the challenge.
        let (mark, detail) = if o.auth_requests > 0 {
            (Mark::Pass, format!("{} challenge(s) seen", o.auth_requests))
        } else if o.lu_accepts > 0 {
            (
                Mark::Warn,
                "registrations accepted without an authentication challenge".into(),
            )
        } else if o.lu_requests > 0 {
            (
                Mark::Info,
                "registrations rejected before authentication".into(),
            )
        } else {
            (Mark::Info, "no registration activity to judge".into())
        };
        add(mark, "rogue", 12);
        Check {
            mark,
            name: "Subscribers are authenticated".into(),
            detail,
        }
    };

    // --- Network identity & neighbours (fake / rogue) ---
    let plmn = {
        let (mark, detail) = match &o.cell {
            Some(c) => {
                let name = crate::e212::describe(&c.mcc, &c.mnc);
                if name.is_empty() {
                    (
                        Mark::Warn,
                        format!("{}/{} not a known operator", c.mcc, c.mnc),
                    )
                } else {
                    (
                        Mark::Info,
                        format!("{name} · {}/{} · LAC {} CID {}", c.mcc, c.mnc, c.lac, c.cid),
                    )
                }
            }
            None => (
                Mark::Warn,
                "cell never broadcast its identity (SI3/4)".into(),
            ),
        };
        add(mark, "fake", 10);
        Check {
            mark,
            name: "PLMN is an allocated operator".into(),
            detail,
        }
    };
    // SI2/2bis/2ter advertise 2G neighbours; 2quater (0x07) advertises 3G/4G.
    let neighbours_2g = o.si_types.iter().any(|t| matches!(t, 0x1A | 0x02 | 0x03));
    let neigh = {
        let (mark, detail) = if neighbours_2g {
            (Mark::Pass, "neighbour list present (SI2/2ter)".into())
        } else {
            (
                Mark::Warn,
                "no neighbour list — may be isolating phones".into(),
            )
        };
        add(mark, "rogue", 10);
        Check {
            mark,
            name: "Advertises neighbour cells".into(),
            detail,
        }
    };
    let neigh_34g = {
        let (mark, detail) = if o.si_types.contains(&0x07) {
            (Mark::Pass, "SI2quater present".into())
        } else {
            (Mark::Warn, "no 3G/4G neighbours advertised".into())
        };
        add(mark, "rogue", 4);
        Check {
            mark,
            name: "Advertises 3G/4G neighbours".into(),
            detail,
        }
    };

    // --- Registration behaviour (misconfigured) ---
    let reg = {
        let imsi_unknown = o.reject_causes.get(&2).copied().unwrap_or(0);
        let (mark, detail) = if o.lu_requests == 0 {
            (Mark::Info, "no registrations observed".into())
        } else if o.lu_accepts > 0 {
            (
                Mark::Pass,
                format!("{} accepted, {} rejected", o.lu_accepts, o.lu_rejects),
            )
        } else if imsi_unknown > 0 && imsi_unknown >= o.lu_rejects {
            (
                Mark::Warn,
                format!(
                    "all {} rejected 'IMSI unknown in HLR' (test/foreign HLR)",
                    o.lu_rejects
                ),
            )
        } else {
            (
                Mark::Warn,
                format!("{} registration(s), none accepted", o.lu_requests),
            )
        };
        add(mark, "misconfigured", 5);
        Check {
            mark,
            name: "Registrations succeed".into(),
            detail,
        }
    };
    // A test cell (operator name says "test") that live handsets from other
    // networks keep reselecting onto and get rejected: not an attack, but a
    // misconfiguration — signalling noise and battery drain for nearby phones.
    let lure = {
        let cell_plmn = o.cell.as_ref().map(|c| (c.mcc.clone(), c.mnc.clone()));
        let is_test = o
            .cell
            .as_ref()
            .map(|c| {
                crate::e212::describe(&c.mcc, &c.mnc)
                    .to_lowercase()
                    .contains("test")
            })
            .unwrap_or(false);
        let foreign: Vec<String> = o
            .home_plmns
            .iter()
            .filter(|(plmn, _)| Some((*plmn).clone()) != cell_plmn)
            .map(|((mcc, mnc), n)| {
                let name = crate::e212::describe(mcc, mnc);
                let who = if name.is_empty() {
                    format!("{mcc}/{mnc}")
                } else {
                    name
                };
                format!("{who} ×{n}")
            })
            .collect();
        let (mark, detail) = if is_test && !foreign.is_empty() {
            (
                Mark::Warn,
                format!("test cell luring live handsets → {}", foreign.join(", ")),
            )
        } else if is_test {
            (
                Mark::Info,
                "test cell; no foreign handsets lured in this window".into(),
            )
        } else if !foreign.is_empty() {
            (Mark::Info, format!("attaches from {}", foreign.join(", ")))
        } else {
            (Mark::Pass, "no foreign-network attaches".into())
        };
        add(mark, "misconfigured", 5);
        Check {
            mark,
            name: "Not luring handsets from other networks".into(),
            detail,
        }
    };

    // --- Neighbourhood & history (needs the pre-scan) ---
    // LAC consistency: a cell of a known operator whose LAC is shared by no other
    // cell of that operator nearby is suspicious — a catcher picks a distinct LAC
    // to force every camping phone to re-register (and reveal its IMSI/TMSI).
    let lac_check = {
        let (mark, detail) = match &o.cell {
            _ if ctx.neighbours.is_empty() => (
                Mark::Info,
                "no pre-scan; run without --no-scan to compare".into(),
            ),
            Some(cell) => {
                let siblings: Vec<&Neighbour> = ctx
                    .neighbours
                    .iter()
                    .filter(|n| {
                        n.mcc == cell.mcc
                            && n.mnc == cell.mnc
                            && !(n.arfcn == o.arfcn && n.cid == cell.cid)
                    })
                    .collect();
                if siblings.is_empty() {
                    (
                        Mark::Info,
                        "no other cells of this operator seen nearby".into(),
                    )
                } else if siblings.iter().any(|n| n.lac == cell.lac) {
                    (
                        Mark::Pass,
                        format!(
                            "LAC {} shared with other {}/{} cells",
                            cell.lac, cell.mcc, cell.mnc
                        ),
                    )
                } else {
                    (
                        Mark::Warn,
                        format!(
                            "LAC {} is not used by any other {}/{} cell nearby (forces re-registration)",
                            cell.lac, cell.mcc, cell.mnc
                        ),
                    )
                }
            }
            None => (Mark::Info, "cell identity unknown".into()),
        };
        add(mark, "rogue", 10);
        Check {
            mark,
            name: "LAC consistent with sibling cells".into(),
            detail,
        }
    };
    // Signal outlier: the scan's (comparable) sweep power — a cell far stronger
    // than its neighbours is very close to you, or artificially close.
    let signal_check = {
        let others: Vec<f64> = ctx
            .neighbours
            .iter()
            .filter(|n| n.arfcn != o.arfcn)
            .map(|n| n.power_db)
            .collect();
        let target = ctx
            .neighbours
            .iter()
            .find(|n| n.arfcn == o.arfcn)
            .map(|n| n.power_db);
        let (mark, detail) = match (target, others.is_empty()) {
            (Some(tp), false) => {
                let mut s = others.clone();
                s.sort_by(f64::total_cmp);
                let median = s[s.len() / 2];
                if tp > median + 12.0 {
                    (
                        Mark::Warn,
                        format!(
                            "{:.0} dB, ~{:.0} dB above the other cells (very/artificially close)",
                            tp,
                            tp - median
                        ),
                    )
                } else {
                    (Mark::Pass, format!("{tp:.0} dB, in line with nearby cells"))
                }
            }
            _ => (Mark::Info, "not enough cells to compare signal".into()),
        };
        add(mark, "rogue", 5);
        Check {
            mark,
            name: "Signal not abnormally strong".into(),
            detail,
        }
    };
    // History: a cell newly appearing in otherwise-static infrastructure is a tell.
    let history_check = {
        let (mark, detail) = match (&ctx.target_known, ctx.had_baseline) {
            (Some(seen), _) => (
                Mark::Pass,
                format!("known since {} (seen {}×)", seen.first, seen.count),
            ),
            (None, true) => (
                Mark::Warn,
                "NEW — not in history; appeared since earlier scans".into(),
            ),
            (None, false) => (
                Mark::Info,
                "baseline recorded (no prior history to compare)".into(),
            ),
        };
        add(mark, "rogue", 10);
        Check {
            mark,
            name: "Cell seen in earlier scans".into(),
            detail,
        }
    };

    // --- Access control & timers (from SI3, TS 44.018 §9.1.35) ---
    // A test/rogue cell that phones must not use should be Cell-Barred; a very
    // short T3212 forces frequent re-registration, a way to harvest identities.
    let is_test = o
        .cell
        .as_ref()
        .map(|c| {
            crate::e212::describe(&c.mcc, &c.mnc)
                .to_lowercase()
                .contains("test")
        })
        .unwrap_or(false);
    let barred = {
        let (mark, detail) = match o.si3.map(|p| p.cell_barred) {
            Some(true) => (
                Mark::Pass,
                "cell barred — phones will not camp on it".into(),
            ),
            Some(false) if is_test => (
                Mark::Warn,
                "test cell is NOT barred — live handsets camp on it (should set Cell Barred)"
                    .into(),
            ),
            Some(false) => (Mark::Info, "not barred (normal for a serving cell)".into()),
            None => (Mark::Info, "no SI3 decoded in this window".into()),
        };
        add(mark, "misconfigured", 5);
        Check {
            mark,
            name: "Cell barring appropriate".into(),
            detail,
        }
    };
    let timer = {
        let (mark, detail) = match o.si3.map(|p| p.t3212_minutes) {
            Some(0) => (Mark::Info, "T3212 = 0 (periodic updating disabled)".into()),
            Some(m) if m < 30 => (
                Mark::Warn,
                format!("T3212 = {m} min — very short; forces frequent re-registration"),
            ),
            Some(m) => (Mark::Pass, format!("T3212 = {m} min — normal")),
            None => (Mark::Info, "no SI3 decoded in this window".into()),
        };
        add(mark, "catching", 10);
        Check {
            mark,
            name: "Re-registration timer (T3212) not abnormally short".into(),
            detail,
        }
    };

    let sections = vec![
        (
            "Identity exposure (tracking / catching)",
            vec![imsi_req, clear_imsi],
        ),
        ("Encryption (sniffing)", vec![ciphering, strength]),
        ("Authentication", vec![auth]),
        (
            "Network identity & neighbours (fake / rogue)",
            vec![plmn, neigh, neigh_34g],
        ),
        ("Access control & timers (SI3)", vec![barred, timer]),
        ("Registration behaviour (misconfigured)", vec![reg, lure]),
        (
            "Neighbourhood & history",
            vec![lac_check, signal_check, history_check],
        ),
    ];
    Scored {
        sections,
        penalty,
        flags,
    }
}

/// Audit one cell and print the report. `hz` is the downlink frequency.
pub fn run(radio: &Radio, socket: &UdpSocket, hz: u64, opts: &Opts) -> Result<()> {
    let colour = std::io::stdout().is_terminal();
    let arfcn = freq::hz_to_arfcn(hz);
    let label = match arfcn {
        Some(a) => format!("{} (ARFCN {a})", freq::mhz(hz)),
        None => freq::mhz(hz),
    };

    // Optional pre-scan: learn the neighbourhood so LAC and signal can be compared.
    let mut ctx = Context::default();
    if opts.scan {
        eprintln!("Scanning for neighbouring cells first…");
        let found = scan::scan(
            radio,
            socket,
            &opts.bands,
            opts.scan_top,
            opts.probe_seconds,
            &mut |_| {},
        )?;
        ctx.neighbours = found.iter().filter_map(Neighbour::from_found).collect();
        eprintln!("  found {} identified cell(s) nearby", ctx.neighbours.len());
    }

    eprintln!(
        "Auditing {label} for {}s (passive; it only listens)…",
        opts.seconds
    );
    // Optionally save every collected frame for evidence / offline validation.
    let mut writer = match &opts.output_dir {
        Some(dir) => {
            let limits = crate::pcapng::Limits {
                rotate_after: Duration::from_secs(3600),
                rotate_bytes: 200 * 1024 * 1024,
                max_total_bytes: 4000 * 1024 * 1024,
            };
            let w = crate::pcapng::Writer::new(dir, limits, format!("cellcap audit-cell {label}"))?;
            eprintln!("  saving frames to {}", dir.display());
            Some(w)
        }
        None => None,
    };
    let obs = collect(radio, socket, hz, opts.seconds, writer.as_mut())?;
    if let Some(w) = writer.as_mut() {
        w.close()?;
    }
    if obs.frames == 0 {
        bail!(
            "no frames decoded on {label}: is it a GSM broadcast channel, and is the SDR attached?"
        );
    }

    // History: look up the target, then record everything seen and save.
    if let Some(path) = &opts.history {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
        let mut hist = History::load(path);
        ctx.had_baseline = !hist.is_empty();
        let seen_now: HashSet<String> = ctx.neighbours.iter().map(Neighbour::key).collect();
        for n in &ctx.neighbours {
            let k = n.key();
            if hist.get(&k).is_some() {
                ctx.known_cells += 1;
            } else {
                ctx.new_cells += 1;
            }
        }
        if let Some(cell) = &obs.cell {
            let tk = history::key(&cell.mcc, &cell.mnc, obs.arfcn, cell.lac, cell.cid);
            ctx.target_known = hist.get(&tk).cloned();
            hist.record(tk, &now);
        }
        for k in seen_now {
            hist.record(k, &now);
        }
        if let Err(e) = hist.save(path) {
            eprintln!("warning: could not write history {}: {e}", path.display());
        }
    }

    let scored = evaluate(&obs, &ctx);
    let score = 100u32.saturating_sub(scored.penalty);
    print_report(
        colour,
        &label,
        &obs,
        &ctx,
        &scored.sections,
        score,
        &scored.flags,
    );
    Ok(())
}

fn c(colour: bool, code: &str) -> &str {
    if colour {
        code
    } else {
        ""
    }
}

#[allow(clippy::too_many_arguments)]
fn print_report(
    colour: bool,
    label: &str,
    obs: &Observations,
    ctx: &Context,
    sections: &[(&str, Vec<Check>)],
    score: u32,
    flags: &BTreeSet<&'static str>,
) {
    let bold = c(colour, BOLD);
    let dim = c(colour, DIM);
    let reset = c(colour, RESET);
    let cyan = c(colour, CYAN);

    println!();
    println!("{bold}╔══════════════════════════════════════════════════════════════╗{reset}");
    println!("{bold}║  cellcap cell audit{reset}                                            {bold}║{reset}");
    println!("{bold}╚══════════════════════════════════════════════════════════════╝{reset}");
    let ident = match &obs.cell {
        Some(cell) => {
            let name = crate::e212::describe(&cell.mcc, &cell.mnc);
            let net = if name.is_empty() {
                format!("{}/{}", cell.mcc, cell.mnc)
            } else {
                name
            };
            format!(
                "{net} · {}/{} · LAC {} CID {}",
                cell.mcc, cell.mnc, cell.lac, cell.cid
            )
        }
        None => "unknown (no SI3/4 seen)".into(),
    };
    println!("  {dim}cell{reset}     {cyan}{label}{reset}");
    println!("  {dim}identity{reset} {ident}");
    println!(
        "  {dim}seen{reset}     {} frames · avg {} dBm · {} registration(s)",
        obs.frames,
        obs.avg_signal(),
        obs.lu_requests
    );
    if !ctx.neighbours.is_empty() {
        println!(
            "  {dim}nearby{reset}   {} cell(s) scanned · {} new, {} known in history",
            ctx.neighbours.len(),
            ctx.new_cells,
            ctx.known_cells
        );
    }

    for (title, checks) in sections {
        println!("\n  {bold}{title}{reset}");
        for ch in checks {
            let (glyph, col) = match ch.mark {
                Mark::Pass => ("✓", GREEN),
                Mark::Warn => ("⚠", YELLOW),
                Mark::Fail => ("✗", RED),
                Mark::Info => ("ℹ", DIM),
            };
            let col = c(colour, col);
            println!(
                "    {col}{glyph}{reset}  {:<34} {dim}{}{reset}",
                ch.name, ch.detail
            );
        }
    }

    // Confidence bar and verdict.
    let filled = (score / 10) as usize;
    let bar: String = "■".repeat(filled) + &"□".repeat(10 - filled);
    let (verdict, vcol) = if score >= 80 {
        ("LIKELY LEGITIMATE", GREEN)
    } else if score >= 55 {
        ("PROBABLY OK — minor anomalies", YELLOW)
    } else if score >= 30 {
        ("SUSPICIOUS — investigate", YELLOW)
    } else {
        ("LIKELY ROGUE / IMSI CATCHER", RED)
    };
    let vcol = c(colour, vcol);
    println!("\n  {bold}Confidence{reset}  {vcol}{bar}{reset}  {vcol}{bold}{score}/100{reset}");
    println!("  {bold}Verdict{reset}     {vcol}{bold}{verdict}{reset}");
    if flags.is_empty() {
        println!("  {dim}No threat indicators tripped.{reset}");
    } else {
        let names: Vec<&str> = flags.iter().copied().collect();
        println!("  {dim}Indicators:{reset} {}", names.join(", "));
    }
    println!(
        "\n  {dim}Heuristics on passively observed behaviour, not proof. A real cell can\n  \
         miss a check (brief window, quiet hour); a catcher can fake one. Keep the\n  \
         pcapng and corroborate before reporting.{reset}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(f: impl FnOnce(&mut Observations)) -> (u32, BTreeSet<&'static str>) {
        let mut o = Observations {
            frames: 100,
            cell: Some(gsmtap::Cell {
                mcc: "238".into(),
                mnc: "01".into(),
                lac: 431,
                cid: 1660,
            }),
            ..Default::default()
        };
        // A healthy baseline: neighbours advertised, strong cipher, auth, accepts.
        o.si_types.extend([0x1B, 0x1C, 0x1A, 0x03, 0x07]);
        o.a5_seen.insert(3);
        o.cipher_cmds = 2;
        o.auth_requests = 2;
        o.lu_requests = 3;
        o.lu_accepts = 3;
        f(&mut o);
        let s = evaluate(&o, &Context::default());
        (100u32.saturating_sub(s.penalty), s.flags)
    }

    #[test]
    fn a_healthy_cell_scores_high() {
        let (score, flags) = with(|_| {});
        assert!(score >= 80, "healthy cell should score high, got {score}");
        assert!(flags.is_empty());
    }

    #[test]
    fn an_imsi_catcher_scores_low() {
        let (score, flags) = with(|o| {
            o.a5_seen.clear();
            o.a5_seen.insert(0); // no ciphering
            o.cipher_cmds = 1;
            o.auth_requests = 0;
            o.identity_requests = 5;
            o.identity_imsi_requests = 5; // forced IMSI identification
            o.paging_clear_imsi = 4;
            o.lu_accepts = 0;
            o.si_types
                .retain(|t| !matches!(t, 0x1A | 0x02 | 0x03 | 0x07)); // hides neighbours
        });
        assert!(score < 30, "catcher should score low, got {score}");
        assert!(flags.contains("sniffing"));
        assert!(flags.contains("catching"));
        assert!(flags.contains("exposure"));
    }

    #[test]
    fn a_test_cell_luring_foreign_handsets_is_flagged() {
        // The 238/66 "(test)" cell pulling in TDC (238/01) and Telia (238/20)
        // handsets that it rejects: still legitimate (stays high), but the
        // 'misconfigured' indicator trips and the detail names who was lured.
        let mut o = Observations {
            frames: 100,
            cell: Some(gsmtap::Cell {
                mcc: "238".into(),
                mnc: "66".into(),
                lac: 22034,
                cid: 35605,
            }),
            ..Default::default()
        };
        o.si_types.extend([0x1B, 0x1C, 0x1A, 0x03, 0x07]);
        o.a5_seen.insert(3);
        o.cipher_cmds = 2;
        o.auth_requests = 2;
        o.lu_requests = 5;
        o.lu_rejects = 5;
        o.reject_causes.insert(2, 5);
        o.home_plmns.insert(("238".into(), "01".into()), 3);
        o.home_plmns.insert(("238".into(), "20".into()), 2);
        let s = evaluate(&o, &Context::default());
        assert!(s.flags.contains("misconfigured"));
        assert!(!s.flags.contains("sniffing"));
        assert!(!s.flags.contains("catching"));
        // Legitimate test cell, so still well clear of the rogue band.
        assert!(100u32.saturating_sub(s.penalty) >= 70);
    }

    #[test]
    fn a_test_cell_is_only_mildly_flagged() {
        // The Telenor test cell: strong cipher, real auth, but all registrations
        // rejected 'IMSI unknown in HLR'. Should stay well above the rogue band.
        let (score, flags) = with(|o| {
            o.lu_accepts = 0;
            o.lu_rejects = 9;
            o.reject_causes.insert(2, 9);
        });
        assert!(
            score >= 80,
            "a test cell should not look rogue, got {score}"
        );
        assert!(!flags.contains("sniffing"));
        assert!(!flags.contains("catching"));
    }
}
