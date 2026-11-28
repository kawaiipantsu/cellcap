//! A tiny on-disk record of which cells have been seen across audits, so a cell
//! that newly appears (or vanishes) in otherwise-static infrastructure can be
//! flagged. Cellular infrastructure is largely static, so a brand-new cell
//! claiming an existing operator is worth a second look — a classic rogue tell.
//!
//! Stored as tab-separated lines to avoid pulling in a serialisation crate:
//! `mcc<TAB>mnc<TAB>arfcn<TAB>lac<TAB>cid<TAB>first_seen<TAB>last_seen<TAB>count`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// When a cell was first and last seen, and how many scans it appeared in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub first: String,
    pub last: String,
    pub count: u32,
}

#[derive(Default)]
pub struct History {
    cells: BTreeMap<String, Seen>,
}

/// A stable key for one cell identity.
pub fn key(mcc: &str, mnc: &str, arfcn: u16, lac: u16, cid: u16) -> String {
    format!("{mcc}/{mnc} ARFCN {arfcn} LAC {lac} CID {cid}")
}

impl History {
    /// Load the history, or an empty one if the file is missing or unreadable
    /// (a best-effort record must never fail an audit).
    pub fn load(path: &Path) -> Self {
        let mut cells = BTreeMap::new();
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                let f: Vec<&str> = line.split('\t').collect();
                if let [mcc, mnc, arfcn, lac, cid, first, last, count] = f[..] {
                    let (Ok(arfcn), Ok(lac), Ok(cid), Ok(count)) = (
                        arfcn.parse::<u16>(),
                        lac.parse::<u16>(),
                        cid.parse::<u16>(),
                        count.parse::<u32>(),
                    ) else {
                        continue;
                    };
                    cells.insert(
                        key(mcc, mnc, arfcn, lac, cid),
                        Seen {
                            first: first.to_string(),
                            last: last.to_string(),
                            count,
                        },
                    );
                }
            }
        }
        History { cells }
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&Seen> {
        self.cells.get(key)
    }

    /// Note that a cell was seen now: new cells get a first-seen stamp, known
    /// ones have their last-seen and count updated.
    pub fn record(&mut self, key: String, now: &str) {
        self.cells
            .entry(key)
            .and_modify(|s| {
                s.last = now.to_string();
                s.count += 1;
            })
            .or_insert(Seen {
                first: now.to_string(),
                last: now.to_string(),
                count: 1,
            });
    }

    /// Persist the history. The parent directory is created if missing.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut out = String::new();
        for (k, s) in &self.cells {
            // Recover the fields from the key for a self-contained line.
            // key = "mcc/mnc ARFCN a LAC l CID c"
            let (plmn, rest) = k.split_once(' ').unwrap_or((k.as_str(), ""));
            let (mcc, mnc) = plmn.split_once('/').unwrap_or((plmn, ""));
            let nums: Vec<&str> = rest
                .split_whitespace()
                .filter(|t| t.chars().all(|c| c.is_ascii_digit()))
                .collect();
            let (a, l, c) = (
                nums.first().copied().unwrap_or("0"),
                nums.get(1).copied().unwrap_or("0"),
                nums.get(2).copied().unwrap_or("0"),
            );
            out.push_str(&format!(
                "{mcc}\t{mnc}\t{a}\t{l}\t{c}\t{}\t{}\t{}\n",
                s.first, s.last, s.count
            ));
        }
        fs::write(path, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("cellcap-hist-{}", std::process::id()));
        let path = dir.join("cell-history.tsv");
        let _ = fs::remove_file(&path);

        let mut h = History::load(&path);
        assert!(h.is_empty());
        let k = key("238", "01", 11, 431, 1660);
        h.record(k.clone(), "2026-11-28 02:00");
        h.record(k.clone(), "2026-11-28 02:30"); // seen again
        h.save(&path).unwrap();

        let h2 = History::load(&path);
        let s = h2.get(&k).expect("cell should be remembered");
        assert_eq!(s.count, 2);
        assert_eq!(s.first, "2026-11-28 02:00");
        assert_eq!(s.last, "2026-11-28 02:30");
        assert!(h2.get(&key("238", "66", 1016, 22034, 35605)).is_none());
        let _ = fs::remove_file(&path);
    }
}
