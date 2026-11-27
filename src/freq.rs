//! Frequencies, ARFCNs and bands (3GPP TS 45.005). All values are downlink.

/// Channel spacing of GSM.
pub const STEP_HZ: u64 = 200_000;

/// Parse a frequency such as `937.2M`, `937200k`, `0.9372G` or `937200000`.
pub fn parse_hz(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let (number, scale) = match t.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('g') => (&t[..t.len() - 1], 1e9),
        Some('m') => (&t[..t.len() - 1], 1e6),
        Some('k') => (&t[..t.len() - 1], 1e3),
        _ => (t, 1.0),
    };
    let v: f64 = number
        .parse()
        .map_err(|_| format!("'{s}' is not a frequency (examples: 937.2M, 937200000)"))?;
    let hz = (v * scale).round();
    if !(1e6..=6e9).contains(&hz) {
        return Err(format!("frequency '{s}' is outside 1 MHz to 6 GHz"));
    }
    Ok(hz as u64)
}

/// Downlink centre frequency of an ARFCN (GSM 850, P/E-GSM 900, DCS 1800).
pub fn arfcn_to_hz(n: u16) -> Option<u64> {
    let n = n as u64;
    Some(match n {
        0..=124 => 935_000_000 + STEP_HZ * n,
        128..=251 => 869_200_000 + STEP_HZ * (n - 128),
        512..=885 => 1_805_200_000 + STEP_HZ * (n - 512),
        975..=1023 => 935_000_000 - STEP_HZ * (1024 - n),
        _ => return None,
    })
}

/// The ARFCN whose centre is within 100 kHz of a downlink frequency.
pub fn hz_to_arfcn(hz: u64) -> Option<u16> {
    (0..=1023u16).find(|n| arfcn_to_hz(*n).is_some_and(|c| c.abs_diff(hz) < STEP_HZ / 2))
}

/// Human form of a frequency, e.g. `937.2 MHz`.
pub fn mhz(hz: u64) -> String {
    format!("{:.1} MHz", hz as f64 / 1e6)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Band {
    pub name: &'static str,
    /// Downlink range covering every channel centre, with a margin.
    pub low_hz: u64,
    pub high_hz: u64,
}

pub const BANDS: &[Band] = &[
    Band {
        name: "GSM900",
        low_hz: 925_000_000,
        high_hz: 960_000_000,
    },
    Band {
        name: "DCS1800",
        low_hz: 1_805_000_000,
        high_hz: 1_880_000_000,
    },
    Band {
        name: "GSM850",
        low_hz: 869_000_000,
        high_hz: 894_000_000,
    },
];

impl Band {
    pub fn parse(s: &str) -> Result<Band, String> {
        let wanted = s.trim().to_ascii_uppercase().replace(['-', '_', ' '], "");
        BANDS
            .iter()
            .copied()
            .find(|b| {
                b.name == wanted || b.name.trim_start_matches(|c: char| c.is_alphabetic()) == wanted
            })
            .ok_or_else(|| format!("unknown band '{s}' (GSM900, DCS1800, GSM850)"))
    }

    /// Every ARFCN whose downlink centre lies in the band.
    pub fn arfcns(&self) -> Vec<u16> {
        (0..=1023u16)
            .filter(|n| arfcn_to_hz(*n).is_some_and(|hz| hz > self.low_hz && hz < self.high_hz))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frequencies() {
        assert_eq!(parse_hz("937.2M"), Ok(937_200_000));
        assert_eq!(parse_hz("937200k"), Ok(937_200_000));
        assert_eq!(parse_hz("0.9372G"), Ok(937_200_000));
        assert_eq!(parse_hz(" 937200000 "), Ok(937_200_000));
        assert!(parse_hz("abc").is_err());
        assert!(parse_hz("12").is_err());
    }

    #[test]
    fn arfcn_round_trip() {
        assert_eq!(arfcn_to_hz(11), Some(937_200_000));
        assert_eq!(arfcn_to_hz(0), Some(935_000_000));
        assert_eq!(arfcn_to_hz(1016), Some(933_400_000));
        assert_eq!(arfcn_to_hz(512), Some(1_805_200_000));
        assert_eq!(arfcn_to_hz(128), Some(869_200_000));
        assert_eq!(arfcn_to_hz(300), None);
        for n in [0u16, 11, 124, 128, 251, 512, 885, 975, 1023] {
            assert_eq!(hz_to_arfcn(arfcn_to_hz(n).unwrap()), Some(n));
        }
        assert_eq!(hz_to_arfcn(937_230_000), Some(11));
        assert_eq!(hz_to_arfcn(100_000_000), None);
    }

    #[test]
    fn bands() {
        assert_eq!(Band::parse("gsm900").unwrap().name, "GSM900");
        assert_eq!(Band::parse("1800").unwrap().name, "DCS1800");
        assert!(Band::parse("LTE").is_err());
        let b = Band::parse("GSM900").unwrap().arfcns();
        assert_eq!(b.len(), 174); // E-GSM: 0-124 and 975-1023
        assert!(b.contains(&11) && b.contains(&1016));
    }
}
