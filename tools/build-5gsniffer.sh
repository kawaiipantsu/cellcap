#!/usr/bin/env bash
#
# Reproducible build of 5GSniffer (research-grade 5G NR PDCCH blind decoder) on
# Debian 13 / clang-19, with UHD. https://github.com/spritelab/5GSniffer
#
# Builds its vendored srsRANRF as a CMake ExternalProject. Under `make -jN` the
# final 5g_sniffer link can race ahead of that external and fail with
# "cannot find -lsrsran_phy"; a second plain `make` links cleanly once the
# external's libsrsran_phy.a exists. We just run make twice.
#
# Prereqs (install once, as root):
#   apt-get install clang cmake make pkg-config libuhd-dev uhd-host \
#     libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev libgtest-dev \
#     libliquid-dev libconfig++-dev libzmq3-dev libspdlog-dev libfmt-dev
#
# Usage from recorded I/Q (live B210 is limited to ~10 MHz FDD NR):
#   cd build && ./src/5g_sniffer ../SpriteLab-Private5G.toml   # edit the .toml first
#
# Third-party GPL tooling, kept OUTSIDE the cellcap (MIT) repo. THUGSred.
set -euo pipefail

ROOT="${1:-$HOME/sdr-tools}"
SRC="$ROOT/5GSniffer"

if [[ ! -d "$SRC" ]]; then
  git clone --recurse-submodules --depth 1 https://github.com/spritelab/5GSniffer.git "$SRC"
fi

cd "$SRC/5gsniffer"
mkdir -p build && cd build
cmake -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ .. >/dev/null
make -j"$(nproc)" || true   # first pass builds the srsRANRF external; link may race
make                        # second pass links 5g_sniffer now that libsrsran_phy.a exists

echo
echo "Built: $SRC/5gsniffer/build/src/5g_sniffer"
