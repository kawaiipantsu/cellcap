//! The legal/ethical disclaimer, shown by `cellcap --disclaimer`,
//! `cellcap disclaimer`, and from the control panel.

/// The disclaimer text (no colour codes, so it is safe to pipe or capture).
pub fn text() -> String {
    format!(
        "cellcap {} — disclaimer\n\
         \n\
         cellcap is a PASSIVE receiver. It never transmits, and it only decodes the\n\
         downlink that base stations already broadcast over the air. Even so, how you may\n\
         receive, record, decode, decrypt and store cellular traffic is regulated, and in\n\
         many countries doing so without authorisation is a criminal offence — regardless\n\
         of whether the content looks sensitive.\n\
         \n\
         By using cellcap you confirm that:\n\
         \n\
           • You have the authorisation you need to receive and record the traffic in your\n\
             location — for example your own test network, a lab, or a written engagement\n\
             with the network operator. When in doubt, assume you need permission.\n\
           • You will only read SIM/UICC cards (extract-kc, sim-info, audit-sim) that you\n\
             own or are explicitly authorised to test, with known test keys.\n\
           • You understand that a capture can contain other people's identifiers — paging\n\
             messages carry temporary (TMSI) and sometimes permanent (IMSI) subscriber\n\
             identities. Those are personal data. Keep capture files private, do not publish\n\
             them, and use `--drop-paging` when you do not need them. Deciphering other\n\
             people's traffic without authorisation is not lawful anywhere cellcap's authors\n\
             are aware of.\n\
           • You, the operator, are solely responsible for complying with the laws and\n\
             regulations that apply to you. Decryption features (A5 via a known Kc) are for\n\
             authorised debugging of networks and test SIMs you are permitted to work with.\n\
         \n\
         cellcap is provided under the MIT licence, WITHOUT WARRANTY OF ANY KIND. The authors\n\
         accept no liability for how it is used. If you are not sure whether something is\n\
         permitted where you are, do not run it until you have checked.\n\
         \n\
         THUGSred · https://thugs.red\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Print the disclaimer to stdout.
pub fn print() {
    print!("{}", text());
}
