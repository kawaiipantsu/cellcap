//! pcapng capture files with rotation and a size-bounded directory.
//!
//! Records use the `WIRESHARK_UPPER_PDU` link type and name the `gsmtap`
//! dissector, so Wireshark decodes the frames with no configuration and no
//! invented IP/UDP headers.

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LINKTYPE_WIRESHARK_UPPER_PDU: u16 = 252;
const EXP_PDU_TAG_DISSECTOR_NAME: u16 = 12;
/// Prefix and suffix of the files this tool owns in the output directory.
const PREFIX: &str = "cellcap-gsm-";
const SUFFIX: &str = ".pcapng";

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn block(kind: u32, mut body: Vec<u8>) -> Vec<u8> {
    pad4(&mut body);
    let total = (body.len() + 12) as u32;
    let mut out = Vec::with_capacity(body.len() + 12);
    out.extend(kind.to_le_bytes());
    out.extend(total.to_le_bytes());
    out.extend(body);
    out.extend(total.to_le_bytes());
    out
}

fn option(body: &mut Vec<u8>, code: u16, value: &[u8]) {
    body.extend(code.to_le_bytes());
    body.extend((value.len() as u16).to_le_bytes());
    body.extend(value);
    pad4(body);
}

/// Section header and one interface description.
pub fn file_header(description: &str) -> Vec<u8> {
    let mut shb = Vec::new();
    shb.extend(0x1A2B_3C4Du32.to_le_bytes());
    shb.extend(1u16.to_le_bytes());
    shb.extend(0u16.to_le_bytes());
    shb.extend((-1i64).to_le_bytes());
    option(
        &mut shb,
        4,
        concat!("cellcap ", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    option(&mut shb, 0, &[]);
    let mut out = block(0x0A0D_0D0A, shb);

    let mut idb = Vec::new();
    idb.extend(LINKTYPE_WIRESHARK_UPPER_PDU.to_le_bytes());
    idb.extend(0u16.to_le_bytes());
    idb.extend(0u32.to_le_bytes());
    option(&mut idb, 2, b"gsmtap");
    option(&mut idb, 3, description.as_bytes());
    option(&mut idb, 0, &[]);
    out.extend(block(1, idb));
    out
}

/// One GSMTAP frame as an enhanced packet block. Timestamps are microseconds.
pub fn packet(timestamp_micros: u64, gsmtap: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(gsmtap.len() + 16);
    data.extend(EXP_PDU_TAG_DISSECTOR_NAME.to_be_bytes());
    data.extend(8u16.to_be_bytes());
    data.extend(b"gsmtap\0\0");
    data.extend([0u8; 4]); // end of options
    data.extend(gsmtap);

    let mut epb = Vec::with_capacity(data.len() + 24);
    epb.extend(0u32.to_le_bytes());
    epb.extend(((timestamp_micros >> 32) as u32).to_le_bytes());
    epb.extend((timestamp_micros as u32).to_le_bytes());
    epb.extend((data.len() as u32).to_le_bytes());
    epb.extend((data.len() as u32).to_le_bytes());
    epb.extend(data);
    block(6, epb)
}

pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct Limits {
    /// Start a new file after this long.
    pub rotate_after: Duration,
    /// Start a new file after this many bytes.
    pub rotate_bytes: u64,
    /// Delete the oldest files when the directory holds more than this.
    pub max_total_bytes: u64,
}

struct Open {
    file: BufWriter<File>,
    path: PathBuf,
    since: Instant,
    bytes: u64,
}

/// Writes frames to the current capture file, rotating and pruning as it goes.
pub struct Writer {
    dir: PathBuf,
    limits: Limits,
    description: String,
    open: Option<Open>,
}

impl Writer {
    pub fn new(dir: &Path, limits: Limits, description: String) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            limits,
            description,
            open: None,
        })
    }

    fn start(&mut self) -> Result<&mut Open> {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let mut path = self.dir.join(format!("{PREFIX}{stamp}{SUFFIX}"));
        let mut n = 1;
        while path.exists() {
            path = self.dir.join(format!("{PREFIX}{stamp}-{n}{SUFFIX}"));
            n += 1;
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        let header = file_header(&self.description);
        let mut file = BufWriter::new(file);
        file.write_all(&header)?;
        eprintln!("info: writing {}", path.display());
        Ok(self.open.insert(Open {
            file,
            path,
            since: Instant::now(),
            bytes: header.len() as u64,
        }))
    }

    /// Append one frame, opening or rotating the file as needed.
    pub fn write(&mut self, timestamp_micros: u64, gsmtap: &[u8]) -> Result<()> {
        let due = self.open.as_ref().is_some_and(|o| {
            o.since.elapsed() >= self.limits.rotate_after || o.bytes >= self.limits.rotate_bytes
        });
        if due {
            self.close()?;
            self.prune();
        }
        let record = packet(timestamp_micros, gsmtap);
        let open = match self.open.as_mut() {
            Some(o) => o,
            None => self.start()?,
        };
        open.file.write_all(&record)?;
        open.bytes += record.len() as u64;
        Ok(())
    }

    /// Push buffered frames to disk so a copy taken now is complete.
    pub fn flush(&mut self) -> Result<()> {
        if let Some(o) = self.open.as_mut() {
            o.file.flush()?;
        }
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        if let Some(mut o) = self.open.take() {
            o.file.flush()?;
            eprintln!("info: closed {} ({} bytes)", o.path.display(), o.bytes);
        }
        Ok(())
    }

    /// Delete the oldest capture files while the directory is over its limit.
    /// Only files this tool names are considered; the open file is kept.
    pub fn prune(&self) {
        let current = self.open.as_ref().map(|o| o.path.clone());
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let mut files: Vec<(PathBuf, u64)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let meta = e.metadata().ok()?;
                (meta.is_file() && name.starts_with(PREFIX) && name.ends_with(SUFFIX))
                    .then(|| (e.path(), meta.len()))
            })
            .collect();
        // The timestamp in the name sorts chronologically.
        files.sort();
        let mut total: u64 = files.iter().map(|(_, len)| len).sum();
        for (path, len) in files {
            if total <= self.limits.max_total_bytes {
                break;
            }
            if Some(&path) == current.as_ref() {
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                eprintln!("info: removed old capture {}", path.display());
                total -= len;
            }
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(b: &[u8]) -> Vec<u32> {
        let (mut at, mut kinds) = (0, Vec::new());
        while at < b.len() {
            let kind = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
            assert_eq!(len % 4, 0);
            assert_eq!(
                u32::from_le_bytes(b[at + len - 4..at + len].try_into().unwrap()) as usize,
                len
            );
            kinds.push(kind);
            at += len;
        }
        kinds
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cellcap-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn blocks_are_well_formed() {
        let mut b = file_header("test");
        b.extend(packet(
            1_795_000_000_000_000,
            &[2, 4, 1, 0, 0, 11, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x49],
        ));
        assert_eq!(blocks(&b), vec![0x0A0D_0D0A, 1, 6]);
        assert!(b.windows(6).any(|w| w == b"gsmtap"));
    }

    #[test]
    fn rotates_by_size_and_prunes_the_oldest() {
        let dir = temp_dir("rotate");
        let limits = Limits {
            rotate_after: Duration::from_secs(3600),
            rotate_bytes: 400,
            max_total_bytes: 900,
        };
        let mut w = Writer::new(&dir, limits, "test".into()).unwrap();
        // A foreign file in the directory is never touched.
        fs::write(dir.join("notes.txt"), vec![0u8; 5000]).unwrap();
        for _ in 0..60 {
            w.write(now_micros(), &[0u8; 39]).unwrap();
        }
        w.close().unwrap();
        w.prune();
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert!(names.contains(&"notes.txt".to_string()));
        let captures: Vec<&String> = names.iter().filter(|n| n.ends_with(SUFFIX)).collect();
        assert!(
            captures.len() >= 2,
            "rotation should have produced several files"
        );
        let total: u64 = captures
            .iter()
            .map(|n| fs::metadata(dir.join(n)).unwrap().len())
            .sum();
        assert!(
            total <= 900,
            "directory is pruned to its limit, has {total}"
        );
        for n in captures {
            blocks(&fs::read(dir.join(n)).unwrap());
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
