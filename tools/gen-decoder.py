#!/usr/bin/env python3
"""Generate cellcap's decoder from the installed grgsm_decode.

The grgsm_decode shipped with gr-gsm calls `gnuradio.pdu.socket_pdu`, a block
that current GNU Radio moved to `gnuradio.network.socket_pdu`, so the stock
tool crashes on every run. This script makes a fixed copy that:

  * uses `network.socket_pdu` (the available block), and
  * takes its GSMTAP UDP ports from the environment
    (CELLCAP_GSMTAP_PORT for the client, CELLCAP_GSMTAP_SERVERPORT for the
    server), so cellcap can collect the frames without clashing on port 4729.

The result is a derivative of grgsm_decode (GPLv3). It is produced on the host
at install time and is NOT distributed with cellcap, which stays MIT.

Usage: gen-decoder.py [SOURCE] OUTPUT
       SOURCE defaults to the grgsm_decode found on PATH.
"""
import os
import shutil
import stat
import sys


def find_source():
    p = shutil.which("grgsm_decode")
    if not p:
        sys.exit("grgsm_decode not found on PATH; install gr-gsm first")
    return p


def main(argv):
    if len(argv) == 2:
        source, output = find_source(), argv[1]
    elif len(argv) == 3:
        source, output = argv[1], argv[2]
    else:
        sys.exit(__doc__)

    src = open(source, encoding="utf-8").read()
    if "socket_pdu" not in src:
        sys.exit(f"{source} does not look like grgsm_decode (no socket_pdu)")

    if "network.socket_pdu" in src and "pdu.socket_pdu" not in src:
        # Already uses the new block; just thread the ports through.
        patched = src
    else:
        patched = src.replace(
            "from gnuradio import pdu\n",
            "from gnuradio import pdu\nfrom gnuradio import network as _ccnet\nimport os as _ccos\n",
            1,
        )
        server = '_ccos.environ.get("CELLCAP_GSMTAP_SERVERPORT", "4730")'
        client = '_ccos.environ.get("CELLCAP_GSMTAP_PORT", "4729")'
        patched = patched.replace(
            'self.socket_pdu_server = pdu.socket_pdu("UDP_SERVER", "127.0.0.1", "4729", 10000) '
            "#added in order to avoid generating ICMP messages",
            'self.socket_pdu_server = _ccnet.socket_pdu("UDP_SERVER", "127.0.0.1", %s, 1500, False)'
            % server,
        )
        patched = patched.replace(
            'self.socket_pdu = pdu.socket_pdu("UDP_CLIENT", "127.0.0.1", "4729", 10000)',
            'self.socket_pdu = _ccnet.socket_pdu("UDP_CLIENT", "127.0.0.1", %s, 1500, False)'
            % client,
        )

    if "_ccnet.socket_pdu" not in patched and "network.socket_pdu" not in patched:
        sys.exit(
            "could not patch the socket_pdu calls; grgsm_decode's layout may have changed"
        )

    with open(output, "w", encoding="utf-8") as f:
        f.write(patched)
    os.chmod(output, os.stat(output).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"wrote {output} (patched from {source})")


if __name__ == "__main__":
    main(sys.argv)
