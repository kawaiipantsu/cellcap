//! A small AT-command client for a serial GSM modem, used to read the current
//! session key Kc from the SIM so captured traffic can be deciphered.
//!
//! It reads EF_Kc (file 0x4F20 under DF_GSM) with the restricted SIM access
//! command `AT+CRSM=176,20256,0,0,9`: READ BINARY, 9 bytes, which is the
//! 8-byte Kc followed by the one-byte ciphering key sequence number. The Kc
//! is the key grgsm_decode wants for A5 decryption.
//!
//! No external crate: the port is configured with termios through libc.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct Modem {
    port: File,
}

/// A key read from the SIM: the 8-byte Kc as hex, and the sequence number.
pub struct Kc {
    pub kc_hex: String,
    pub sequence: u8,
}

/// Location information from EF_LOCI: the temporary identity and where it is
/// registered.
pub struct Loci {
    pub tmsi: String,
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub status: &'static str,
}

/// A read of the SIM files useful for debugging and deciphering GSM.
#[derive(Default)]
pub struct SimInfo {
    pub imsi: Option<String>,
    pub kc: Option<Kc>,
    pub kc_gprs: Option<Kc>,
    pub loci: Option<Loci>,
}

// GSM SIM elementary file identifiers.
const EF_IMSI: u16 = 0x6F07;
const EF_KC: u16 = 0x4F20;
const EF_KC_GPRS: u16 = 0x6F52;
const EF_LOCI: u16 = 0x6F7E;

impl Modem {
    pub fn open(path: &Path, baud: u32) -> Result<Modem> {
        let port = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("opening serial port {}", path.display()))?;
        configure(port.as_raw_fd(), baud)
            .with_context(|| format!("configuring serial port {}", path.display()))?;
        Ok(Modem { port })
    }

    /// Discard anything already waiting from the modem.
    fn drain(&mut self) {
        let mut buf = [0u8; 512];
        while let Ok(n) = self.port.read(&mut buf) {
            if n == 0 {
                break;
            }
        }
    }

    /// Send one AT command and collect the reply up to its final result code.
    pub fn command(&mut self, cmd: &str, timeout: Duration) -> Result<String> {
        self.drain();
        self.port
            .write_all(format!("{cmd}\r").as_bytes())
            .context("writing to the modem")?;
        self.port.flush().ok();

        let mut out = String::new();
        let mut buf = [0u8; 512];
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.port.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    out.push_str(&String::from_utf8_lossy(&buf[..n]));
                    // Final result codes per 3GPP TS 27.007.
                    if out.contains("\r\nOK\r\n")
                        || out.contains("\r\nERROR\r\n")
                        || out.contains("+CME ERROR")
                        || out.contains("+CMS ERROR")
                    {
                        return Ok(out);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e).context("reading from the modem"),
            }
        }
        if out.trim().is_empty() {
            bail!("no response from the modem on this port — is it the right device and baud?");
        }
        Ok(out)
    }

    /// READ BINARY of a transparent elementary file: returns the status words
    /// and the data bytes.
    pub fn read_binary(&mut self, file_id: u16, length: u8) -> Result<(u8, u8, Vec<u8>)> {
        let cmd = format!("AT+CRSM=176,{file_id},0,0,{length}");
        let resp = self.command(&cmd, Duration::from_secs(6))?;
        let (sw1, sw2, hex) = crsm_payload(&resp)?;
        Ok((sw1, sw2, hex_to_bytes(&hex)))
    }
}

/// Bytes from a hex string, ignoring any spaces.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len() / 2)
        .filter_map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Decode an IMSI from EF_IMSI: a length byte, then swapped-nibble BCD whose
/// first nibble is a parity/type indicator.
fn decode_imsi(b: &[u8]) -> Option<String> {
    let len = *b.first()? as usize;
    let data = b.get(1..1 + len)?;
    let mut s = String::new();
    s.push(char::from_digit((data[0] >> 4) as u32, 10)?);
    for &byte in &data[1..] {
        s.push(char::from_digit((byte & 0x0F) as u32, 10)?);
        let hi = byte >> 4;
        if hi != 0x0F {
            s.push(char::from_digit(hi as u32, 10)?);
        }
    }
    Some(s)
}

/// Decode EF_LOCI: 4-byte TMSI, 5-byte LAI, time, update status.
fn decode_loci(b: &[u8]) -> Option<Loci> {
    let b = b.get(..11)?;
    let (mcc, mnc) = crate::gsmtap::plmn(&b[4..7])?;
    let status = match b[10] & 0x07 {
        0 => "updated",
        1 => "not updated",
        2 => "PLMN not allowed",
        3 => "location area not allowed",
        _ => "reserved",
    };
    Some(Loci {
        tmsi: b[..4].iter().map(|x| format!("{x:02X}")).collect(),
        mcc,
        mnc,
        lac: u16::from_be_bytes([b[7], b[8]]),
        status,
    })
}

/// Turn EF_Kc bytes (8-byte key + 1 sequence byte) into a [`Kc`].
fn kc_from_bytes(b: &[u8]) -> Option<Kc> {
    let key = b.get(..8)?;
    let kc_hex: String = key.iter().map(|x| format!("{x:02X}")).collect();
    if kc_hex == "FFFFFFFFFFFFFFFF" {
        return None;
    }
    Some(Kc {
        kc_hex,
        sequence: b.get(8).copied().unwrap_or(0xFF) & 0x07,
    })
}

/// Put the port into raw 8N1 at the given baud, no flow control.
fn configure(fd: i32, baud: u32) -> Result<()> {
    let speed = baud_constant(baud);
    // SAFETY: tcgetattr/tcsetattr act on our own fd with a local termios.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr");
        }
        libc::cfmakeraw(&mut t);
        libc::cfsetispeed(&mut t, speed);
        libc::cfsetospeed(&mut t, speed);
        t.c_cflag |= libc::CLOCAL | libc::CREAD;
        t.c_cflag &= !libc::CRTSCTS;
        t.c_cc[libc::VMIN] = 0;
        t.c_cc[libc::VTIME] = 0;
        if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcsetattr");
        }
        // Back to blocking-with-no-data semantics for reads.
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
    Ok(())
}

fn baud_constant(baud: u32) -> libc::speed_t {
    match baud {
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        460800 => libc::B460800,
        921600 => libc::B921600,
        _ => libc::B115200,
    }
}

/// Parse the hex payload and status words out of a `+CRSM:` reply.
fn crsm_payload(resp: &str) -> Result<(u8, u8, String)> {
    let line = resp
        .lines()
        .find(|l| l.contains("+CRSM:"))
        .ok_or_else(|| anyhow::anyhow!("no +CRSM response; the reply was:\n{}", resp.trim()))?;
    let after = line.split("+CRSM:").nth(1).unwrap_or("").trim();
    // Form: sw1,sw2[,"HEX"]
    let mut parts = after.splitn(3, ',');
    let sw1: u8 = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| anyhow::anyhow!("could not read SW1 from '{after}'"))?;
    let sw2: u8 = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let hex = parts
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .to_string();
    Ok((sw1, sw2, hex))
}

/// Read the session key Kc from the SIM in the modem on `path`.
pub fn read_kc(path: &Path, baud: u32) -> Result<Kc> {
    let mut modem = Modem::open(path, baud)?;
    // Wake the modem and turn echo off; ignore failures (some need a moment).
    let _ = modem.command("AT", Duration::from_secs(2));
    let _ = modem.command("ATE0", Duration::from_secs(2));
    // READ BINARY of EF_Kc (0x4F20 = 20256), 9 bytes.
    let resp = modem.command("AT+CRSM=176,20256,0,0,9", Duration::from_secs(6))?;
    let (sw1, sw2, hex) = crsm_payload(&resp)?;
    if sw1 != 0x90 {
        bail!(
            "the SIM returned status {sw1:02X} {sw2:02X} for EF_Kc, not 90 00. \
             The SIM may need a PIN, or no GSM session key is stored yet \
             (force a 2G attach/authentication first)."
        );
    }
    if hex.len() < 16 {
        bail!("EF_Kc was shorter than expected: '{hex}'");
    }
    let kc_hex = hex[..16].to_uppercase();
    let sequence = u8::from_str_radix(&hex[16..18.min(hex.len())], 16).unwrap_or(0xFF) & 0x07;
    if kc_hex == "FFFFFFFFFFFFFFFF" {
        bail!("EF_Kc is empty (all FF): the SIM holds no GSM session key yet. Force a 2G authentication, then read again.");
    }
    Ok(Kc { kc_hex, sequence })
}

/// Read the SIM files useful for debugging: IMSI, Kc, GPRS Kc and location
/// information. Files that cannot be read are left out, not treated as errors,
/// since not every SIM has every file.
pub fn read_sim_info(path: &Path, baud: u32) -> Result<SimInfo> {
    let mut modem = Modem::open(path, baud)?;
    let _ = modem.command("AT", Duration::from_secs(2));
    let _ = modem.command("ATE0", Duration::from_secs(2));
    // At least one read must succeed, or the modem/SIM is not reachable.
    let imsi = modem.read_binary(EF_IMSI, 9).ok();
    let kc = modem.read_binary(EF_KC, 9).ok();
    let kc_gprs = modem.read_binary(EF_KC_GPRS, 9).ok();
    let loci = modem.read_binary(EF_LOCI, 11).ok();
    if imsi.is_none() && kc.is_none() && loci.is_none() {
        bail!("no SIM files could be read — is the modem on this port and is a SIM present?");
    }
    let ok = |r: &Option<(u8, u8, Vec<u8>)>| -> Option<Vec<u8>> {
        r.as_ref()
            .filter(|(sw1, _, _)| *sw1 == 0x90)
            .map(|(_, _, b)| b.clone())
    };
    Ok(SimInfo {
        imsi: ok(&imsi).as_deref().and_then(decode_imsi),
        kc: ok(&kc).as_deref().and_then(kc_from_bytes),
        kc_gprs: ok(&kc_gprs).as_deref().and_then(kc_from_bytes),
        loci: ok(&loci).as_deref().and_then(decode_loci),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_crsm_reply() {
        let r = "\r\n+CRSM: 144,0,\"1122334455667788 05\"\r\n\r\nOK\r\n";
        let (sw1, sw2, hex) = crsm_payload(r).unwrap();
        assert_eq!((sw1, sw2), (144, 0));
        // Spaces inside the quotes are kept as-is for the caller to slice.
        assert!(hex.starts_with("1122334455667788"));
    }

    #[test]
    fn rejects_a_reply_without_crsm() {
        assert!(crsm_payload("\r\nERROR\r\n").is_err());
    }

    #[test]
    fn reads_kc_and_sequence_from_clean_hex() {
        // Build a fake reply with no spaces: 8 bytes Kc + 1 byte sequence (0x05).
        let r = "+CRSM: 144,0,\"A1B2C3D4E5F6071805\"\r\nOK\r\n";
        let (sw1, _, hex) = crsm_payload(r).unwrap();
        assert_eq!(sw1, 144);
        assert_eq!(&hex[..16], "A1B2C3D4E5F60718");
        assert_eq!(u8::from_str_radix(&hex[16..18], 16).unwrap() & 0x07, 5);
    }
}
