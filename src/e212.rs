//! E.212 MCC/MNC lookup: turn the numeric codes a cell broadcasts into a
//! readable operator and country, e.g. 238/01 -> "TDC A/S · Denmark".
//!
//! The air interface only carries the numbers; these names come from the ITU
//! E.212 assignments (the same table Wireshark ships). The operator list is
//! focused on the Nordics and major networks and degrades gracefully — an
//! unknown MNC still shows the country, and an unknown MCC just shows the codes.
//! It is easy to extend: add a row to OPERATORS or COUNTRIES.

/// MCC -> country. Broad coverage of the networks a passive receiver is likely
/// to see; extend as needed.
const COUNTRIES: &[(&str, &str)] = &[
    ("202", "Greece"), ("204", "Netherlands"), ("206", "Belgium"), ("208", "France"),
    ("212", "Monaco"), ("213", "Andorra"), ("214", "Spain"), ("216", "Hungary"),
    ("218", "Bosnia & Herzegovina"), ("219", "Croatia"), ("220", "Serbia"), ("222", "Italy"),
    ("225", "Vatican"), ("226", "Romania"), ("228", "Switzerland"), ("230", "Czechia"),
    ("231", "Slovakia"), ("232", "Austria"), ("234", "United Kingdom"), ("235", "United Kingdom"),
    ("238", "Denmark"), ("240", "Sweden"), ("242", "Norway"), ("244", "Finland"),
    ("246", "Lithuania"), ("247", "Latvia"), ("248", "Estonia"), ("250", "Russia"),
    ("255", "Ukraine"), ("257", "Belarus"), ("259", "Moldova"), ("260", "Poland"),
    ("262", "Germany"), ("266", "Gibraltar"), ("268", "Portugal"), ("270", "Luxembourg"),
    ("272", "Ireland"), ("274", "Iceland"), ("276", "Albania"), ("278", "Malta"),
    ("280", "Cyprus"), ("282", "Georgia"), ("283", "Armenia"), ("284", "Bulgaria"),
    ("286", "Turkey"), ("288", "Faroe Islands"), ("290", "Greenland"), ("292", "San Marino"),
    ("293", "Slovenia"), ("294", "North Macedonia"), ("295", "Liechtenstein"), ("297", "Montenegro"),
    ("302", "Canada"), ("308", "Saint Pierre & Miquelon"), ("310", "United States"),
    ("311", "United States"), ("312", "United States"), ("313", "United States"),
    ("316", "United States"), ("330", "Puerto Rico"), ("334", "Mexico"), ("338", "Jamaica"),
    ("340", "French Caribbean"), ("342", "Barbados"), ("346", "Cayman Islands"),
    ("350", "Bermuda"), ("352", "Grenada"), ("360", "Saint Vincent"), ("362", "Curaçao"),
    ("364", "Bahamas"), ("366", "Dominica"), ("368", "Cuba"), ("370", "Dominican Republic"),
    ("372", "Haiti"), ("374", "Trinidad & Tobago"), ("376", "Turks & Caicos"),
    ("400", "Azerbaijan"), ("401", "Kazakhstan"), ("402", "Bhutan"), ("404", "India"),
    ("405", "India"), ("406", "India"), ("410", "Pakistan"), ("412", "Afghanistan"),
    ("413", "Sri Lanka"), ("414", "Myanmar"), ("415", "Lebanon"), ("416", "Jordan"),
    ("417", "Syria"), ("418", "Iraq"), ("419", "Kuwait"), ("420", "Saudi Arabia"),
    ("421", "Yemen"), ("422", "Oman"), ("424", "United Arab Emirates"), ("425", "Israel"),
    ("426", "Bahrain"), ("427", "Qatar"), ("428", "Mongolia"), ("429", "Nepal"),
    ("432", "Iran"), ("434", "Uzbekistan"), ("436", "Tajikistan"), ("437", "Kyrgyzstan"),
    ("438", "Turkmenistan"), ("440", "Japan"), ("441", "Japan"), ("450", "South Korea"),
    ("452", "Vietnam"), ("454", "Hong Kong"), ("455", "Macau"), ("456", "Cambodia"),
    ("457", "Laos"), ("460", "China"), ("466", "Taiwan"), ("467", "North Korea"),
    ("470", "Bangladesh"), ("472", "Maldives"), ("502", "Malaysia"), ("505", "Australia"),
    ("510", "Indonesia"), ("515", "Philippines"), ("520", "Thailand"), ("525", "Singapore"),
    ("528", "Brunei"), ("530", "New Zealand"), ("602", "Egypt"), ("603", "Algeria"),
    ("604", "Morocco"), ("605", "Tunisia"), ("606", "Libya"), ("607", "Gambia"),
    ("608", "Senegal"), ("611", "Guinea"), ("612", "Côte d'Ivoire"), ("613", "Burkina Faso"),
    ("615", "Togo"), ("616", "Benin"), ("617", "Mauritius"), ("620", "Ghana"),
    ("621", "Nigeria"), ("624", "Cameroon"), ("630", "DR Congo"), ("631", "Angola"),
    ("633", "Seychelles"), ("639", "Kenya"), ("640", "Tanzania"), ("641", "Uganda"),
    ("643", "Mozambique"), ("645", "Zambia"), ("647", "Réunion"), ("648", "Zimbabwe"),
    ("649", "Namibia"), ("650", "Malawi"), ("651", "Lesotho"), ("652", "Botswana"),
    ("655", "South Africa"), ("702", "Belize"), ("704", "Guatemala"), ("706", "El Salvador"),
    ("708", "Honduras"), ("710", "Nicaragua"), ("712", "Costa Rica"), ("714", "Panama"),
    ("716", "Peru"), ("722", "Argentina"), ("724", "Brazil"), ("730", "Chile"),
    ("732", "Colombia"), ("734", "Venezuela"), ("736", "Bolivia"), ("738", "Guyana"),
    ("740", "Ecuador"), ("744", "Paraguay"), ("746", "Suriname"), ("748", "Uruguay"),
];

/// (MCC, MNC) -> operator. Nordics are complete; elsewhere the major networks.
/// MNC is the canonical form a cell broadcasts (leading zeros kept).
const OPERATORS: &[(&str, &str, &str)] = &[
    // Denmark (238)
    ("238", "01", "TDC A/S"), ("238", "02", "Telenor"), ("238", "03", "MIGway"),
    ("238", "04", "Nuuday (altibox)"), ("238", "05", "ApS KBUS"), ("238", "06", "Hi3G (3)"),
    ("238", "07", "Mundio Mobile"), ("238", "09", "Dansk Beredskabskommunikation"),
    ("238", "10", "TDC A/S"), ("238", "12", "Lycamobile"), ("238", "13", "Compatel"),
    ("238", "20", "Telia"), ("238", "23", "GlobalConnect"), ("238", "28", "CoolTEL"),
    ("238", "30", "Telia"), ("238", "40", "Ericsson Danmark"), ("238", "43", "MobiWeb"),
    ("238", "66", "Telenor (test)"), ("238", "77", "Telenor"),
    // Sweden (240)
    ("240", "01", "Telia"), ("240", "02", "Hi3G (3)"), ("240", "04", "Telenor"),
    ("240", "05", "Telenor"), ("240", "07", "Telenor"), ("240", "08", "Telenor"),
    ("240", "10", "Spring Mobil"), ("240", "24", "Net4Mobility"),
    // Norway (242)
    ("242", "01", "Telenor"), ("242", "02", "Telia"), ("242", "03", "Hi3G (3)"),
    ("242", "05", "Telia"), ("242", "06", "ice"), ("242", "08", "Telia"), ("242", "09", "ice"),
    // Finland (244)
    ("244", "03", "DNA"), ("244", "05", "Elisa"), ("244", "07", "Nokia"),
    ("244", "09", "Telia"), ("244", "12", "DNA"), ("244", "14", "Telia"), ("244", "21", "Telia"),
    // Germany (262)
    ("262", "01", "Telekom"), ("262", "02", "Vodafone"), ("262", "03", "Telefónica (o2)"),
    ("262", "07", "Telefónica (o2)"), ("262", "08", "Telefónica (o2)"),
    // United Kingdom (234)
    ("234", "10", "O2"), ("234", "15", "Vodafone"), ("234", "20", "Three"),
    ("234", "30", "EE"), ("234", "33", "EE"), ("234", "50", "JT"),
    // Netherlands (204)
    ("204", "04", "Vodafone"), ("204", "08", "KPN"), ("204", "16", "T-Mobile"),
    // France (208)
    ("208", "01", "Orange"), ("208", "10", "SFR"), ("208", "15", "Free"),
    ("208", "20", "Bouygues"),
    // United States (310/311/312)
    ("310", "260", "T-Mobile"), ("310", "410", "AT&T"), ("311", "480", "Verizon"),
    ("310", "120", "Sprint"),
];

/// Pad/normalise an MNC so the scanner path ("1") matches a broadcast key ("01").
fn mnc_variants(mnc: &str) -> [String; 3] {
    [
        mnc.to_string(),
        format!("{mnc:0>2}"),
        format!("{mnc:0>3}"),
    ]
}

/// The operator name for a PLMN, if known.
pub fn operator(mcc: &str, mnc: &str) -> Option<&'static str> {
    let vars = mnc_variants(mnc);
    OPERATORS
        .iter()
        .find(|(m, n, _)| *m == mcc && vars.iter().any(|v| v == n))
        .map(|(_, _, name)| *name)
}

/// The country for an MCC, if known.
pub fn country(mcc: &str) -> Option<&'static str> {
    COUNTRIES
        .iter()
        .find(|(m, _)| *m == mcc)
        .map(|(_, name)| *name)
}

/// A readable label for a PLMN: "TDC A/S · Denmark", or "Denmark", or "" when
/// neither is known. Never includes the raw codes (callers show those).
pub fn describe(mcc: &str, mnc: &str) -> String {
    match (operator(mcc, mnc), country(mcc)) {
        (Some(op), Some(c)) => format!("{op} · {c}"),
        (Some(op), None) => op.to_string(),
        (None, Some(c)) => c.to_string(),
        (None, None) => String::new(),
    }
}

/// Just the operator, falling back to the country, for a compact column.
pub fn short(mcc: &str, mnc: &str) -> String {
    operator(mcc, mnc)
        .map(str::to_string)
        .or_else(|| country(mcc).map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn danish_tdc() {
        assert_eq!(operator("238", "01"), Some("TDC A/S"));
        assert_eq!(country("238"), Some("Denmark"));
        assert_eq!(describe("238", "01"), "TDC A/S · Denmark");
    }

    #[test]
    fn scanner_mnc_without_leading_zero_matches() {
        // grgsm_scanner yields "1"; it must still resolve to the "01" row.
        assert_eq!(operator("238", "1"), Some("TDC A/S"));
    }

    #[test]
    fn graceful_degradation() {
        assert_eq!(describe("238", "99"), "Denmark"); // unknown MNC, known country
        assert_eq!(describe("999", "99"), ""); // unknown everything
        assert_eq!(short("238", "99"), "Denmark");
        assert_eq!(short("238", "20"), "Telia");
    }
}
