//! `cellcap audit-sim`: read the SIM Service Table and report the toolkit and
//! OTA features that make up the attack surface for known SIM/UICC attacks
//! (Simjacker, WIBattack and other SMS-PP OTA abuse).
//!
//! This reads capability flags only (EF_SST, 3GPP TS 51.011). It does not
//! prove a SIM is exploitable: whether the S@T Browser or WIB applet is
//! actually installed, and how strong the OTA keys are, can only be told by an
//! active test (e.g. SRLabs SIMTester). A flagged service is a *precondition*
//! for the matching attack, not a confirmation of it.

use crate::atmodem::Modem;
use anyhow::Result;
use std::io::IsTerminal;
use std::path::Path;

const EF_SST: u16 = 0x6F38;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Risk {
    High,
    Medium,
    Info,
}

/// One service we report on: its TS 51.011 number, a name, the risk if it is
/// active, and why it matters.
struct Check {
    service: usize,
    name: &'static str,
    risk: Risk,
    note: &'static str,
}

const CHECKS: &[Check] = &[
    Check {
        service: 29,
        name: "Proactive SIM (card application toolkit)",
        risk: Risk::Info,
        note: "the SIM can act on its own; prerequisite for toolkit attacks",
    },
    Check {
        service: 26,
        name: "Data download via SMS-PP",
        risk: Risk::High,
        note: "enables OTA commands over SMS — the Simjacker / WIBattack vector",
    },
    Check {
        service: 25,
        name: "Data download via SMS-CB",
        risk: Risk::Medium,
        note: "OTA push over cell broadcast",
    },
    Check {
        service: 42,
        name: "RUN AT COMMAND",
        risk: Risk::High,
        note: "a toolkit applet can drive the modem with AT commands",
    },
    Check {
        service: 28,
        name: "Call control by SIM",
        risk: Risk::Medium,
        note: "the SIM can redirect or alter outgoing calls",
    },
    Check {
        service: 37,
        name: "MO SMS control by SIM",
        risk: Risk::Medium,
        note: "the SIM can redirect or alter outgoing SMS",
    },
    Check {
        service: 41,
        name: "USSD in call control",
        risk: Risk::Info,
        note: "USSD strings can be acted on during call control",
    },
];

/// Where an attack lives, and so whether a SIM read can speak to it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// On the card itself — a SIM read can check its preconditions.
    Uicc,
    /// On the handset, OS or baseband — not visible from the SIM.
    DeviceOs,
}

/// A known SMS/UICC attack from the catalogue. For UICC attacks, `needs` lists
/// the EF_SST services that must be active for the SIM to be reachable by it,
/// and `confirm` says what an active test would still have to establish.
struct Attack {
    name: &'static str,
    year: &'static str,
    surface: Surface,
    needs: &'static [usize],
    confirm: &'static str,
}

const ATTACKS: &[Attack] = &[
    // --- UICC: the SIM read can check delivery preconditions. ---
    Attack {
        name: "Simjacker",
        year: "2019",
        surface: Surface::Uicc,
        needs: &[26, 29],
        confirm: "S@T Browser applet installed (needs applet enumeration / active OTA test)",
    },
    Attack {
        name: "WIBattack",
        year: "2019",
        surface: Surface::Uicc,
        needs: &[26, 29],
        confirm: "WIB applet installed (active OTA test)",
    },
    Attack {
        name: "Rooting SIM Cards (weak OTA keys)",
        year: "2013",
        surface: Surface::Uicc,
        needs: &[26],
        confirm: "weak OTA keys (single DES) — active OTA signature test, e.g. SIMtester",
    },
    Attack {
        name: "MONKEYCALENDAR (STK implant)",
        year: "2013",
        surface: Surface::Uicc,
        needs: &[26, 29],
        confirm: "a planted STK applet exfiltrating via SMS (applet enumeration)",
    },
    Attack {
        name: "GOPHERSET (STK implant)",
        year: "2013",
        surface: Surface::Uicc,
        needs: &[26, 29],
        confirm: "a planted STK applet exfiltrating via SMS (applet enumeration)",
    },
    Attack {
        name: "SIM Toolkit Attack",
        year: "2011",
        surface: Surface::Uicc,
        needs: &[29, 26],
        confirm: "a malicious STK applet (applet enumeration)",
    },
    Attack {
        name: "SMS auto-reply (STK)",
        year: "2010",
        surface: Surface::Uicc,
        needs: &[29, 26],
        confirm: "an STK auto-reply applet (applet enumeration)",
    },
    // --- Device/OS: handset, OS or baseband — not visible from a SIM read. ---
    Attack {
        name: "OMA CP provisioning phishing",
        year: "2019",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Visual Voicemail IMAP attack",
        year: "2019",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Samsung WAP Push / OMA CP",
        year: "2017",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "PINGSMS 2.0",
        year: "2015",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "CoreTelephony Class 0 SMS",
        year: "2015",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "iPhone Springboard Class 0 SMS",
        year: "2014",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Android Nexus Class 0 SMS",
        year: "2013",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "SIM bricking (Android)",
        year: "2012",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "iOS text spoofing",
        year: "2012",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Samsung WAP Push",
        year: "2012",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "SMS of Death",
        year: "2010",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Fuzzing the Phone in your Phone",
        year: "2009",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "TAFT / spoofed MMS notification",
        year: "2009",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Windows Mobile 5/6 WAP Push",
        year: "2009",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "SonyEricsson WAP Push",
        year: "2009",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Curse of Silence",
        year: "2008",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Hijacking Mobile Data Connections",
        year: "2008",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Hide Sender Field (Windows Mobile)",
        year: "2007",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Siemens 45 long image name",
        year: "2003",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Nokia 6210 malformed vCard",
        year: "2003",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
    Attack {
        name: "Nokia malformed SMS UDH",
        year: "2001",
        surface: Surface::DeviceOs,
        needs: &[],
        confirm: "",
    },
];

/// Whether service `n` (1-based) is allocated and activated in an EF_SST body.
/// Two bits per service: bit 0 allocated, bit 1 activated.
fn available(table: &[u8], n: usize) -> Option<bool> {
    let byte = *table.get((n - 1) / 4)?;
    let shift = ((n - 1) % 4) * 2;
    let allocated = (byte >> shift) & 1 != 0;
    let activated = (byte >> (shift + 1)) & 1 != 0;
    Some(allocated && activated)
}

pub fn run(path: &Path, baud: u32) -> Result<()> {
    let colour = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let paint = |c: &str, s: &str| {
        if colour {
            format!("{c}{s}{RESET}")
        } else {
            s.to_string()
        }
    };

    let mut modem = Modem::open(path, baud)?;
    let _ = modem.command("AT", std::time::Duration::from_secs(2));
    let _ = modem.command("ATE0", std::time::Duration::from_secs(2));
    let (sw1, sw2, table) = modem.read_binary(EF_SST, 20)?;
    if sw1 != 0x90 {
        anyhow::bail!("could not read EF_SST (status {sw1:02X} {sw2:02X}); the SIM may need a PIN");
    }

    println!(
        "SIM attack-surface audit — EF_SST (2G SIM Service Table, 3GPP TS 51.011)\n{}",
        paint(DIM, &format!("  raw: {}", hex(&table)))
    );
    println!();

    let mut high = 0;
    let mut medium = 0;
    for c in CHECKS {
        let on = available(&table, c.service).unwrap_or(false);
        let (glyph, gcol) = match (on, c.risk) {
            (true, Risk::High) => ("[!!]", RED),
            (true, Risk::Medium) => ("[! ]", YELLOW),
            (true, Risk::Info) => ("[i ]", DIM),
            (false, _) => ("[ok]", GREEN),
        };
        if on && c.risk == Risk::High {
            high += 1;
        }
        if on && c.risk == Risk::Medium {
            medium += 1;
        }
        let state = if on { "active " } else { "off    " };
        println!(
            "  {}  svc {:<2}  {} {}",
            paint(gcol, glyph),
            c.service,
            paint(
                if on { BOLD } else { DIM },
                &format!("{state} {:<38}", c.name)
            ),
            paint(DIM, c.note)
        );
    }

    println!();
    let verdict = if high > 0 {
        paint(
            RED,
            &format!("{high} high-risk service(s) active: OTA/toolkit attack surface is present."),
        )
    } else if medium > 0 {
        paint(
            YELLOW,
            &format!("{medium} medium-risk service(s) active; no SMS-PP OTA download."),
        )
    } else {
        paint(
            GREEN,
            "No OTA/toolkit download services active on this SIM.",
        )
    };
    println!("{verdict}");

    // UICC attacks: report whether the SIM's delivery preconditions are met.
    println!(
        "\n{}",
        paint(BOLD, "Known UICC attacks — SIM-side preconditions")
    );
    let met = |needs: &[usize]| needs.iter().all(|&n| available(&table, n).unwrap_or(false));
    for a in ATTACKS.iter().filter(|a| a.surface == Surface::Uicc) {
        let present = met(a.needs);
        let (glyph, col) = if present {
            ("[!!]", RED)
        } else {
            ("[ok]", GREEN)
        };
        let needs: Vec<String> = a.needs.iter().map(|n| format!("svc {n}")).collect();
        let status = if present {
            format!(
                "precondition MET ({}) — to confirm: {}",
                needs.join("+"),
                a.confirm
            )
        } else {
            format!("precondition absent ({} not active)", needs.join("+"))
        };
        println!(
            "  {}  {} {}",
            paint(col, glyph),
            paint(
                if present { BOLD } else { DIM },
                &format!("{:<34}", format!("{} ({})", a.name, a.year))
            ),
            paint(DIM, &status)
        );
    }

    // Device/OS attacks: a SIM read cannot speak to these at all.
    println!(
        "\n{}",
        paint(BOLD, "Device/OS attacks — not determinable from the SIM")
    );
    println!(
        "{}",
        paint(
            DIM,
            "  Handset, OS or baseband flaws in how SMS/WAP-push/OMA-CP/MMS are parsed. A card read\n\
             says nothing about them; they are found by observing inbound traffic against a target\n\
             device. Listed here only so the audit's scope is clear:"
        )
    );
    let names: Vec<String> = ATTACKS
        .iter()
        .filter(|a| a.surface == Surface::DeviceOs)
        .map(|a| format!("{} ({})", a.name, a.year))
        .collect();
    for chunk in names.chunks(2) {
        println!("    {}", paint(DIM, &chunk.join("   ·   ")));
    }

    println!(
        "\n{}",
        paint(
            DIM,
            "Note: EF_SST flags are capability preconditions, not proof of exploitability. Confirming\n\
             an installed S@T/WIB/STK applet or weak OTA keys (MSL, single-DES vs AES) needs an active\n\
             OTA test such as SRLabs SIMtester. A met precondition means the SIM can be reached by the\n\
             attack's delivery path, not that it is vulnerable."
        )
    );
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_service_bits() {
        // Service 1 available: byte0 bits 0,1 set = 0b11 = 0x03.
        assert_eq!(available(&[0x03], 1), Some(true));
        // Service 1 allocated but not activated: 0b01.
        assert_eq!(available(&[0x01], 1), Some(false));
        // Service 2 lives in byte0 bits 2,3.
        assert_eq!(available(&[0b1100], 2), Some(true));
        assert_eq!(available(&[0b1100], 1), Some(false));
        // Service 5 is the first in byte1.
        assert_eq!(available(&[0x00, 0x03], 5), Some(true));
        // Service 26 (SMS-PP download): (26-1)/4 = byte 6, bit ((25)%4)*2 = 2.
        let mut t = vec![0u8; 8];
        t[6] = 0b0000_1100; // bits 2,3 set -> service 26 active
        assert_eq!(available(&t, 26), Some(true));
        assert_eq!(available(&t, 25), Some(false));
        // Out of range is None.
        assert_eq!(available(&[0x00], 50), None);
    }
}
