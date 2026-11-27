# Changelog

All notable changes to cellcap. Versions follow [Semantic Versioning](https://semver.org).

## [1.2.0] — 2026-11-27

### Added
- **"What's in the packet" detail** — the live feed names the kind of data a message carries, not
  just the message name: Paging already lists each identity kind (`by TMSI + IMSI`, with an IMSI in
  the clear flagged); now *Identity Request* shows which identity it asks for (an IMSI-catcher tell),
  *Ciphering Mode Command* shows the A5 algorithm it starts (or "no ciphering"), *Authentication
  Request* notes the RAND challenge, and TMSI reallocation / MM information / call setup / SMS are
  annotated. *Location Updating Accept* names the LAI it registers to; *Location Updating Reject* /
  *CM Service Reject* give the cause (IMSI unknown in HLR, PLMN not allowed, …); *Channel Release*
  gives the RR cause. Best-effort and byte-guarded; Wireshark remains authoritative.

## [1.1.0] — 2026-11-27

### Added
- **Operator / country names** — MCC/MNC are resolved through an E.212 lookup (`src/e212.rs`) and
  shown as e.g. `TDC A/S · Denmark · 238/01` in the live feed, the scan table's NETWORK column, and
  the dashboard's Cells tab. The raw codes are always kept; the name is data in one table, not logic
  (ARFCN is never assumed to belong to an operator — the operator comes from the broadcast MNC).
- **Decoded events in the live view** — dedicated-channel signalling (SDCCH/SACCH/FACCH) is parsed
  into readable, colour-coded events: Location Updating, Authentication, Ciphering Mode, Identity,
  CM Service, SMS (CP), call control (Setup/Alerting/Connect/Release), and more. Best-effort, to
  confirm the flow matches Wireshark; Wireshark stays authoritative.
- **Channel column** — every live line (stream and dashboard) shows the GSMTAP channel
  (BCCH/CCCH/SDCCH/SACCH…).

## [1.0.0] — 2026-11-27

cellcap grew from a GSM-only pcap writer into a multi-RAT capture suite with an interactive
control panel. First stable release.

### Added
- **Interactive control panel** — run `cellcap` with no arguments (or `cellcap ui`): a home
  menu of every mode, a form to set its options, and a live scrollable output pane, all in one
  TUI. It drives the same subcommands under the hood.
- **LTE (4G) capture** — `cellcap lte` drives LTESniffer to write the downlink control plane as a
  Wireshark MAC-LTE pcap. `--earfcn` (FDD bands 1–66) or `--freq`, `--antennas`, `--cell-id`/`--prb`.
- **UHD / USRP support** — `--device uhd` across `scan`/`run`/`decode`; `scan` falls back to
  `grgsm_scanner` for devices with no power-sweep tool. B210 and clones.
- **Remote live Wireshark** — `cellcap run --gsmtap-udp HOST:PORT` mirrors every GSMTAP frame to a
  remote UDP endpoint (direct on 4729, or Wireshark's `udpdump` listener on 5555).
- **SIM tools** — `extract-kc`, `sim-info`, and `audit-sim` (SIM toolkit / OTA attack-surface
  audit from EF_SST, Simjacker/WIB class) over a serial modem.
- **`decode`** — dedicated/ciphered channels (SDCCH, TCH) from the SDR or a cfile, with optional
  A5 decryption given the session key Kc.
- **`inspect`** — summarise a capture file without an SDR; **`check`** — host/SDR preflight.
- **`--disclaimer`** / `cellcap disclaimer` — legal/ethical notice.
- Documented README with screenshots and per-mode guides; `tools/build-ltesniffer.sh` and
  `tools/build-5gsniffer.sh` for the out-of-tree LTE/5G tooling.

### Notes
- cellcap remains **receive-only** — it never transmits. See the Disclaimer.
- Live LTE, UHD, and the control panel's live-capture path are built and unit-tested; full
  on-air validation with a USRP B210 is pending that hardware.

## [0.1.0] — 2026-11-26

- Initial release: passive GSM broadcast/control-channel capture to pcapng (`scan`, `run`),
  a live dashboard (`run --interactive`), pcapng rotation, and the systemd service.
