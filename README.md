# cellcap

Passive cellular capture for Wireshark. cellcap listens to the broadcast and common
control channels of GSM cells with a software-defined radio and writes what it decodes
to pcapng files. It never transmits.

It runs as a foreground command or as a systemd service. Either way the result is a
directory of capture files you copy to your own machine and open in Wireshark.

## What it does

- **Scans** a band: a power sweep finds the channels that carry something, then each is
  decoded briefly. Only a channel whose broadcast information decodes is reported as a cell.
- **Captures** one or more channels, chosen by `--freq`, `--arfcn` or the scan.
- **Writes pcapng** itself, with rotation by time and size and a cap on the directory size.
- **Supervises the radio**: the decoder is restarted when it exits or goes quiet, and in
  scan mode a dead channel triggers a new scan.
- **Shows a live dashboard** (`run --interactive`): tabbed terminal UI with the message
  feed, the cells seen, the capture files and a log — to confirm good data is being collected.
- **Decodes dedicated channels** (`decode`): SDCCH and traffic channels, with optional A5
  decryption when you supply the session key.
- **Reads a capture back** (`inspect`) and **checks the host** (`check`), no SDR needed.

The radio demodulation is done by [gr-gsm](https://github.com/ptrkrysik/gr-gsm), which
cellcap starts and stops. cellcap is everything around it.

## Commands

| Command | What it does |
| --- | --- |
| `cellcap check` | Preflight checklist: required tools and an SDR, with ✓/✗ per item. |
| `cellcap scan` | Find cells and print a table. |
| `cellcap run` | Capture broadcast/control channels to pcapng (the service runs this). |
| `cellcap decode` | Decode a dedicated/ciphered channel (SDCCH, TCH) from a recording. |
| `cellcap inspect FILE…` | Summarise a capture file, like `tshark -z`. |
| `cellcap extract-kc [DEVICE]` | Read the SIM's session key Kc from a serial modem. |
| `cellcap sim-info [DEVICE]` | Read IMSI, Kc, GPRS Kc and TMSI/LAI from the SIM. |
| `cellcap audit-sim [DEVICE]` | Report the SIM's toolkit/OTA attack surface (Simjacker/WIB class). |

## Requirements

- An SDR that gr-osmosdr supports. Tested with a Nooelec RTL-SDR v5. HackRF support is
  implemented but has not been tested on hardware.
- `gr-gsm` (provides `grgsm_livemon_headless`, and `grgsm_capture`/`grgsm_decode` for `decode`).
- For scanning: `rtl_power` (package `rtl-sdr`) or `hackrf_sweep` (package `hackrf`).
- For `extract-kc`: a serial GSM modem with the test SIM (e.g. `/dev/ttyUSB0`).
- Rust 1.80 or newer to build.

Debian: `apt install gr-gsm rtl-sdr hackrf`. Run `cellcap check` to verify everything.

> **Note on `decode`.** The `grgsm_decode` shipped with gr-gsm calls a GNU Radio block
> (`pdu.socket_pdu`) that current GNU Radio moved to `network.socket_pdu`, so the stock
> tool crashes. `make install` (or `make decoder`) generates a fixed copy,
> `cellcap-decode`, from it with `tools/gen-decoder.py`. That generated file is a
> derivative of grgsm_decode (GPLv3) and is produced on your host, not shipped in this
> repository.

## Build and install

```bash
make release
sudo make install     # binary, service, the 'cellcap' user, /etc/default/cellcap
sudo systemctl enable --now cellcap
```

## Use

```bash
# What cells are around?
cellcap scan
cellcap scan --band GSM900 --band DCS1800 --device hackrf=0

# Capture one channel into the current directory until Ctrl-C
cellcap run --freq 937.2M --output-dir .
cellcap run --arfcn 11 --output-dir .

# Scan, then capture the strongest cell of one network
cellcap run --plmn 23801 --output-dir .

# Watch a live dashboard while capturing (no saving)
cellcap run --arfcn 11 --interactive --no-write
```

### Dashboard (`--interactive`)

`--interactive` (`-i`) opens a live terminal dashboard with tabs:

- **Overview** — current channel and phase, frame counters, the cells seen, and the
  capture directory size.
- **Live** — one readable line per decoded message, rolling.
- **Cells** — a table of identified cells (ARFCN, MCC/MNC/LAC/CID, signal, frame count).
- **Captures** — the capture files on disk with sizes and timestamps.
- **Log** — info and warnings from the capture loop and the radio tools.

Move between tabs with `Tab`/`←`/`→` or number keys `1`–`5`; quit with `q`. It needs a
real terminal. System information that repeats unchanged is shown once; subscriber
identities are named by kind only (TMSI/IMSI), never by value. `--no-write` watches
without saving.

### Line view (`--stream`)

`--stream` prints one line per message to stdout instead of the dashboard — useful for
logging or piping, and for headless terminals:

```
14:43:35.378  ARFCN 11     -27 dBm  System Information 3        MCC 238 MNC 01 LAC 431 CID 1660
14:43:36.103  ARFCN 11     -27 dBm  Immediate Assignment        a phone is sent to SDCCH/8 on timeslot 3
14:43:36.367  ARFCN 11     -27 dBm  Paging                      1 phone(s) called, by TMSI
```

Colours are used on a terminal; set `NO_COLOR=1` to turn them off.

`cellcap scan` prints a table:

```
ARFCN  FREQUENCY    POWER   MCC  MNC  LAC    CID    BROADCAST
11     937.2 MHz      3.2   238  01   431    1660   yes
94     953.8 MHz    -10.1   -    -    -      -      no
```

`BROADCAST no` means the channel carries power but no decodable broadcast channel: a
traffic carrier, or something that is not GSM.

### Main options of `cellcap run`

| Option | Default | Meaning |
| --- | --- | --- |
| `--freq`, `--arfcn` | none | Channel(s) to capture. Without either, cellcap scans. |
| `--band` | `GSM900` | Band(s) to scan: `GSM900`, `DCS1800`, `GSM850`. |
| `--cells` | 1 | How many scanned cells to capture, cycling between them. |
| `--plmn` | any | Only pick cells of this network (MCC then MNC, e.g. `23801`). |
| `--dwell` | 120 s | Time on each channel when capturing several. |
| `--device` | `rtl=0` | SDR, as gr-osmosdr arguments (`rtl=0`, `hackrf=0`). |
| `--gain`, `--ppm` | 40 dB, 0 | RF gain and frequency correction. |
| `--output-dir` | `/var/lib/cellcap/captures` | Where the capture files go. |
| `--rotate-minutes`, `--rotate-mb` | 60, 50 | Start a new file after this time or size. |
| `--max-total-mb` | 2000 | Oldest captures are deleted above this directory size. |
| `--drop-paging` | off | Leave paging messages out (see Privacy). |
| `--interactive`, `-i` | off | Live terminal dashboard (needs a terminal). |
| `--stream` | off | One readable line per message on stdout instead of the dashboard. |
| `--no-write` | off | With `--interactive`/`--stream`: do not save capture files. |
| `--port` | 47290 | Local UDP port the decoder delivers to; the decoder itself uses the next one. |

One SDR receives one channel at a time, so several channels are captured in turn, not
at once.

## Decoding dedicated and ciphered channels

`cellcap run` captures the broadcast and common control channels. To decode a **dedicated**
channel — SDCCH signalling (Location Updating, authentication, SMS) or a traffic channel —
use `cellcap decode`. It records a short cfile (or takes one you give) and runs the decoder
over it, writing the result to a pcapng.

```bash
# Decode the SDCCH/8 on timeslot 1, recording 20 s from the SDR
cellcap decode --arfcn 11 --mode sdcch8 --timeslot 1

# Decode the combined control channel on C0 (SDCCH/4) from an existing recording
cellcap decode --arfcn 11 --mode bcch-sdcch4 --timeslot 0 --cfile grab.cfile

# A ciphered channel, with the A5 session key
cellcap decode --arfcn 11 --mode sdcch8 --timeslot 1 --cipher-a5 1 --cipher-kc 1234567890ABCDEF
```

Modes: `bcch`, `bcch-sdcch4`, `sdcch8`, `tchf`, `tchh`. Decryption happens inside the
decoder; Wireshark cannot do A5 itself, so a ciphered channel without the key shows only
ciphered frames. Supply the **session key Kc** with `--cipher-kc` (see *Keys from the SIM*);
the SIM master key **Ki cannot be used directly** — derive Kc from Ki and the RAND first.

This needs the generated `cellcap-decode` (see the note under *Requirements*). On a
combined-C0 cell the SDCCH/4 is already present in an ordinary `run` capture; `decode` is
for standalone SDCCH/8 on other timeslots and for traffic channels.

> gr-gsm here has **no GPRS/PDTCH decoder**, and none of these tools follow a
> **frequency-hopping** traffic channel; `decode` works on one fixed channel at a time.

## Reading a capture back

```bash
cellcap inspect cellcap-gsm-20261127T085130Z.pcapng
```

prints frame counts by message type and channel, the cells seen and the time span — a
quick way to confirm a file holds what you want before opening Wireshark.

## Keys and identities from the SIM

With the test SIM in a serial GSM modem you can read the files needed to decipher and to
filter a capture to your own device:

```bash
cellcap extract-kc /dev/ttyUSB0      # just the A5 session key Kc (+ CKSN)
cellcap sim-info   /dev/ttyUSB0      # IMSI, Kc, GPRS Kc, and TMSI + LAI from EF_LOCI
```

Use the **IMSI** (or the **TMSI**) in Wireshark to filter a capture to your own phone,
e.g. `gsm_a.imsi == "<imsi>"`, instead of sifting through others on the same ARFCN. Pass
the **Kc** to `cellcap decode --cipher-kc`. The Kc read from EF_Kc is the one from the last
GSM authentication, so force a 2G attach before reading if you need a fresh one. These
values are secrets — keep them off shared machines and out of capture files you circulate.

### Auditing the SIM

```bash
cellcap audit-sim /dev/ttyUSB0
```

reads the SIM Service Table (EF_SST) and reports the toolkit and OTA features that make up
the attack surface for known SIM/UICC attacks — above all **Data download via SMS-PP**, the
precondition for Simjacker and WIBattack. It then maps a catalogue of known attacks:

- **UICC attacks** (Simjacker, WIBattack, Rooting SIM Cards, MONKEYCALENDAR, GOPHERSET, SIM
  Toolkit Attack, STK auto-reply) — whether the SIM's *delivery preconditions* are met.
- **Device/OS attacks** (WAP push, OMA CP, class-0 SMS, Curse of Silence, malformed UDH/vCard,
  MMS notification, …) — listed as **not determinable from the SIM**: these are handset, OS or
  baseband flaws found by observing inbound traffic, not by reading a card.

These are capability flags, not proof: whether the S@T Browser / WIB / STK applet is installed
and how strong the OTA keys are (MSL, single-DES vs AES) can only be told by an active OTA test
(e.g. SRLabs SIMtester). A met precondition means the SIM is *reachable* by the attack's
delivery path, not that it is vulnerable.

> The modem may be in use by another program (e.g. an SMS gateway); stop that first so the
> port is free. `ModemManager` can also hold modems.

## The service

Settings are in `/etc/default/cellcap` as the arguments of `cellcap run`. After a change:
`sudo systemctl restart cellcap`. The log is in the journal: `journalctl -u cellcap -f`.

The service runs as the unprivileged user `cellcap`, which is in group `plugdev` for
access to the SDR.

## Getting the captures

Files are named `cellcap-gsm-<UTC time>.pcapng` in `/var/lib/cellcap/captures`. The
newest file is still being written; it is flushed every two seconds, so a copy taken at
any moment opens fine.

```bash
scp 'root@host:/var/lib/cellcap/captures/*.pcapng' .
wireshark cellcap-gsm-*.pcapng
```

Useful Wireshark display filters:

| Filter | Shows |
| --- | --- |
| `gsm_a.dtap.msg_rr_type == 0x1b` | System Information Type 3: network, area and cell identity |
| `gsm_a.dtap.msg_rr_type == 0x21` | Paging requests |
| `gsm_a.dtap.msg_rr_type == 0x3f` | Immediate assignments |
| `gsmtap.chan_type == 1` | Broadcast channel only |
| `gsmtap.chan_type == 0x87` | SDCCH/4 SACCH |
| `gsm_a.imsi == "<imsi>"` | Only your own device (from `sim-info`) |
| `gsmtap.arfcn == 11` | One channel |

Wireshark's **Telephony → GSM** menu summarises the same data.

## What is and is not in a capture

- **In:** the cell's system information, paging and immediate assignments. On a combined-C0
  cell the SDCCH/4 and its SACCH are present too, so the DTAP signalling there (Location
  Updating, authentication, SMS on signalling) is decoded in the clear until ciphering starts.
- **With `decode` and a key:** ciphered SDCCH/8 and traffic channels (see *Decoding*).
- **Not in a plain `run`:** standalone SDCCH/8 on other timeslots, traffic channels, and
  anything ciphered without the key.
- **Only the downlink** is received: what the base station sends, not what phones send.

## Privacy and law

Paging messages contain the temporary (TMSI) and sometimes permanent (IMSI) identities
of other people's phones. Treat capture files as personal data: keep them private and do
not publish them. `--drop-paging` leaves these messages out entirely.

Receiving is passive, but rules on intercepting and storing radio traffic differ by
country. Check what applies to you before running this continuously.

## Limits

- GSM only for now. The layout leaves room for other sources.
- An RTL-SDR with an R820T tuner cannot reach the 1800 MHz downlink band.
- The scan needs `rtl_power` or `hackrf_sweep`; other SDRs must be given `--freq`.
- **No GPRS/PDTCH decode:** this gr-gsm has no packet-data demapper.
- **Frequency-hopping traffic channels are not dehopped** — `decode` works on one fixed
  channel at a time, even given the MAIO/HSN.
- `decode` relies on the generated `cellcap-decode`, because the packaged `grgsm_decode`
  is broken against current GNU Radio.
- Deciphering uses the session key Kc (A5), not the SIM master key Ki.
