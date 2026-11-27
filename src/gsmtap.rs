//! Just enough GSMTAP and GSM layer 3 parsing to label and filter frames.
//! The frames themselves are written to the capture unmodified.

/// Fixed part of a GSMTAP version 2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub arfcn: u16,
    pub uplink: bool,
    pub signal_dbm: i8,
    pub channel: u8,
    pub len: usize,
}

/// What a frame carries, as far as this tool cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// System Information of the given message type (0x19 = SI1, 0x1B = SI3, …).
    SystemInfo(u8),
    Paging,
    ImmediateAssignment,
    Other,
}

/// Identity of a cell as broadcast in System Information Type 3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub cid: u16,
}

const TYPE_UM: u8 = 1;
const CHANNEL_BCCH: u8 = 1;
const CHANNEL_CCCH: u8 = 2;

pub fn header(packet: &[u8]) -> Option<Header> {
    if packet.len() < 16 || packet[0] != 2 || packet[2] != TYPE_UM {
        return None;
    }
    let len = packet[1] as usize * 4;
    if len < 16 || packet.len() < len {
        return None;
    }
    let arfcn = u16::from_be_bytes([packet[4], packet[5]]);
    Some(Header {
        arfcn: arfcn & 0x3FFF,
        uplink: arfcn & 0x4000 != 0,
        signal_dbm: packet[6] as i8,
        channel: packet[12],
        len,
    })
}

/// The layer 3 message on a broadcast or common control channel: after the
/// L2 pseudo length come the protocol discriminator and the message type.
pub fn rr_message(packet: &[u8]) -> Option<(u8, &[u8])> {
    let h = header(packet)?;
    if !matches!(h.channel, CHANNEL_BCCH | CHANNEL_CCCH) {
        return None;
    }
    let l3 = &packet[h.len..];
    // Protocol discriminator 6 = radio resource management.
    (l3.len() >= 3 && l3[1] & 0x0F == 0x06).then(|| (l3[2], &l3[3..]))
}

pub fn kind(packet: &[u8]) -> Kind {
    match rr_message(packet) {
        Some((t @ (0x00..=0x07 | 0x18..=0x1F), _)) => Kind::SystemInfo(t),
        Some((0x21 | 0x22 | 0x24, _)) => Kind::Paging,
        Some((0x3F, _)) => Kind::ImmediateAssignment,
        _ => Kind::Other,
    }
}

/// Name of a System Information message type, e.g. `3` or `2quater`.
pub fn system_info_name(message_type: u8) -> String {
    match message_type {
        0x19 => "1".into(),
        0x1A => "2".into(),
        0x1B => "3".into(),
        0x1C => "4".into(),
        0x1D => "5".into(),
        0x1E => "6".into(),
        0x1F => "7".into(),
        0x18 => "8".into(),
        0x02 => "2bis".into(),
        0x03 => "2ter".into(),
        0x07 => "2quater".into(),
        0x05 => "5bis".into(),
        0x06 => "5ter".into(),
        0x04 => "9".into(),
        0x00 => "13".into(),
        t => format!("0x{t:02X}"),
    }
}

/// The kinds of subscriber identity a paging request addresses, e.g.
/// `["TMSI", "IMSI"]`. Empty for a filler request that pages nobody. The
/// identities themselves are not returned.
pub fn paged(packet: &[u8]) -> Vec<&'static str> {
    let Some((t, body)) = rr_message(packet) else {
        return Vec::new();
    };
    let name = |first: u8| match first & 0x07 {
        1 => Some("IMSI"),
        2 => Some("IMEI"),
        3 => Some("IMEISV"),
        4 => Some("TMSI"),
        _ => None,
    };
    let mut out = Vec::new();
    match t {
        // Type 1: one or two mobile identities, each with its own type.
        0x21 => {
            let Some(len) = body.get(1).map(|l| *l as usize) else {
                return out;
            };
            out.extend(body.get(2).copied().and_then(name));
            let next = 2 + len;
            if body.get(next) == Some(&0x17) {
                out.extend(body.get(next + 2).copied().and_then(name));
            }
        }
        // Type 2: two TMSIs and an optional third identity.
        0x22 => {
            out.extend(["TMSI", "TMSI"]);
            if body.get(9) == Some(&0x17) {
                out.extend(body.get(11).copied().and_then(name));
            }
        }
        // Type 3: four TMSIs.
        0x24 => out.extend(["TMSI"; 4]),
        _ => {}
    }
    out
}

/// Where an immediate assignment sends the phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assignment {
    /// A dedicated channel of the given kind on a timeslot.
    Dedicated { channel: &'static str, timeslot: u8 },
    /// A packet data (GPRS) resource.
    Packet,
}

pub fn assignment(packet: &[u8]) -> Option<Assignment> {
    let (0x3F, body) = rr_message(packet)? else {
        return None;
    };
    // High nibble: dedicated mode or TBF; bit 0x10 set means packet access.
    if body.first()? & 0x10 != 0 {
        return Some(Assignment::Packet);
    }
    let description = *body.get(1)?;
    let channel = match description >> 3 {
        0b00001 => "TCH/F",
        0b00010 | 0b00011 => "TCH/H",
        0b00100..=0b00111 => "SDCCH/4",
        0b01000..=0b01111 => "SDCCH/8",
        _ => "channel",
    };
    Some(Assignment::Dedicated {
        channel,
        timeslot: description & 0x07,
    })
}

/// Location area (MCC, MNC, LAC) from a System Information Type 4 frame.
pub fn location_area(packet: &[u8]) -> Option<(String, String, u16)> {
    let (0x1C, body) = rr_message(packet)? else {
        return None;
    };
    let (mcc, mnc) = plmn(body.get(..3)?)?;
    Some((mcc, mnc, u16::from_be_bytes([*body.get(3)?, *body.get(4)?])))
}

/// MCC and MNC from their three BCD octets. Used for both broadcast frames
/// and the SIM's location information.
pub(crate) fn plmn(b: &[u8]) -> Option<(String, String)> {
    let digit = |n: u8| char::from_digit((n & 0x0F) as u32, 10);
    let mcc: String = [digit(b[0]), digit(b[0] >> 4), digit(b[1])]
        .into_iter()
        .collect::<Option<_>>()?;
    let mut mnc: String = [digit(b[2]), digit(b[2] >> 4)]
        .into_iter()
        .collect::<Option<_>>()?;
    if b[1] >> 4 != 0x0F {
        mnc.push(digit(b[1] >> 4)?);
    }
    Some((mcc, mnc))
}

/// Cell identity from a System Information Type 3 frame.
pub fn cell(packet: &[u8]) -> Option<Cell> {
    let (0x1B, body) = rr_message(packet)? else {
        return None;
    };
    // Cell identity (2), then location area identification: MCC/MNC as BCD
    // digits (3) and the location area code (2).
    let b = body.get(..7)?;
    let (mcc, mnc) = plmn(&b[2..5])?;
    Some(Cell {
        mcc,
        mnc,
        lac: u16::from_be_bytes([b[5], b[6]]),
        cid: u16::from_be_bytes([b[0], b[1]]),
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A GSMTAP Um frame on `channel` of ARFCN 11 carrying `l3`.
    pub fn frame(channel: u8, l3: &[u8]) -> Vec<u8> {
        let mut p = vec![
            2, 4, TYPE_UM, 0, 0, 11, 0xC4, 0, 0, 0, 0, 1, channel, 0, 0, 0,
        ];
        p.extend_from_slice(l3);
        p
    }

    /// System Information Type 3 for MCC 238, MNC 01, LAC 0x01AF, CID 0x067C.
    pub fn si3() -> Vec<u8> {
        frame(
            CHANNEL_BCCH,
            &[
                0x49, 0x06, 0x1B, 0x06, 0x7C, 0x32, 0xF8, 0x10, 0x01, 0xAF, 0x00,
            ],
        )
    }

    #[test]
    fn reads_the_header() {
        let h = header(&si3()).unwrap();
        assert_eq!(
            (h.arfcn, h.uplink, h.signal_dbm, h.channel),
            (11, false, -60, 1)
        );
        assert!(header(&[2, 4, 1]).is_none());
        assert!(header(&[1; 20]).is_none()); // other GSMTAP version
    }

    #[test]
    fn labels_messages() {
        assert_eq!(kind(&si3()), Kind::SystemInfo(0x1B));
        assert_eq!(
            kind(&frame(CHANNEL_CCCH, &[0x15, 0x06, 0x21, 0x00])),
            Kind::Paging
        );
        assert_eq!(
            kind(&frame(CHANNEL_CCCH, &[0x2D, 0x06, 0x3F, 0x00])),
            Kind::ImmediateAssignment
        );
        // A dedicated-channel frame is never read as a common-channel message.
        assert_eq!(kind(&frame(7, &[0x15, 0x06, 0x21, 0x00])), Kind::Other);
    }

    #[test]
    fn paging_identity_kinds() {
        // Type 1 with a TMSI, then with an IMSI and a second TMSI.
        let one = frame(
            CHANNEL_CCCH,
            &[0x25, 0x06, 0x21, 0x00, 0x05, 0xF4, 1, 2, 3, 4],
        );
        assert_eq!(paged(&one), vec!["TMSI"]);
        let two = frame(
            CHANNEL_CCCH,
            &[
                0x4D, 0x06, 0x21, 0x00, 0x08, 0x29, 1, 2, 3, 4, 5, 6, 7, 0x17, 0x05, 0xF4, 1, 2, 3,
                4,
            ],
        );
        assert_eq!(paged(&two), vec!["IMSI", "TMSI"]);
        // The idle filler pages nobody.
        let filler = frame(CHANNEL_CCCH, &[0x15, 0x06, 0x21, 0x00, 0x01, 0xF0, 0x2B]);
        assert!(paged(&filler).is_empty());
        assert_eq!(
            paged(&frame(CHANNEL_CCCH, &[0x59, 0x06, 0x24, 0x00])).len(),
            4
        );
        assert!(paged(&si3()).is_empty());
    }

    #[test]
    fn immediate_assignment_target() {
        // Dedicated mode, SDCCH/8 subchannel on timeslot 1.
        let p = frame(CHANNEL_CCCH, &[0x2D, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x0B]);
        assert_eq!(
            assignment(&p),
            Some(Assignment::Dedicated {
                channel: "SDCCH/8",
                timeslot: 1
            })
        );
        let p = frame(CHANNEL_CCCH, &[0x2D, 0x06, 0x3F, 0x10, 0x00]);
        assert_eq!(assignment(&p), Some(Assignment::Packet));
        assert_eq!(assignment(&si3()), None);
    }

    #[test]
    fn names_and_location_area() {
        assert_eq!(system_info_name(0x1B), "3");
        assert_eq!(system_info_name(0x07), "2quater");
        assert_eq!(system_info_name(0x00), "13");
        let si4 = frame(
            CHANNEL_BCCH,
            &[0x31, 0x06, 0x1C, 0x32, 0xF8, 0x10, 0x01, 0xAF, 0x00],
        );
        assert_eq!(location_area(&si4), Some(("238".into(), "01".into(), 431)));
    }

    #[test]
    fn cell_identity_from_si3() {
        let c = cell(&si3()).unwrap();
        assert_eq!(
            (c.mcc.as_str(), c.mnc.as_str(), c.lac, c.cid),
            ("238", "01", 0x01AF, 0x067C)
        );
        // Three-digit MNC.
        let p = frame(
            CHANNEL_BCCH,
            &[0x49, 0x06, 0x1B, 0, 1, 0x13, 0x00, 0x62, 0, 2],
        );
        assert_eq!(cell(&p).unwrap().mnc, "260");
        assert!(cell(&frame(CHANNEL_CCCH, &[0x15, 0x06, 0x21, 0x00])).is_none());
    }
}
