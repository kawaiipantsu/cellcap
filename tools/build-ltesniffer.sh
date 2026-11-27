#!/usr/bin/env bash
#
# Reproducible build of LTESniffer (passive LTE downlink sniffer) on Debian 13
# (trixie) / GCC 14, with UHD support for the USRP B210.
#
# LTESniffer (https://github.com/SysSec-KAIST/LTESniffer) is built on FALCON +
# a pinned, older srsRAN that predates GCC 14. GCC 14 promotes several legacy-C
# diagnostics to hard errors and newer libstdc++ no longer transitively pulls in
# <array>/<string>, so a stock build fails. This script clones, then applies the
# minimal patches needed to compile, then builds with the srsUE/ENB/EPC *apps*
# disabled (LTESniffer only needs the srsRAN *libraries* + FALCON + the UHD RF
# driver). Result: build/src/LTESniffer, a UHD-linked binary.
#
# Prereqs (install once, as root):
#   apt-get install uhd-host libuhd-dev libsoapysdr-dev \
#     libglib2.0-dev libudev-dev libcurl4-gnutls-dev libboost-all-dev \
#     qtdeclarative5-dev libqt5charts5-dev libfftw3-dev libmbedtls-dev \
#     libboost-program-options-dev libconfig++-dev libsctp-dev python3-mako
#   uhd_images_downloader        # fetches usrp_b210_fpga.bin
#
# This is third-party GPL tooling kept OUTSIDE the cellcap repo. THUGSred.
set -euo pipefail

ROOT="${1:-$HOME/sdr-tools}"
SRC="$ROOT/LTESniffer"
JOBS="$(nproc)"

if [[ ! -d "$SRC" ]]; then
  git clone --depth 1 https://github.com/SysSec-KAIST/LTESniffer.git "$SRC"
fi

# ---- Patch 1: LTESniffer's own C flags (GCC 14 default-errors) --------------
# GCC 14 makes implicit-int / implicit-function-declaration / int-conversion /
# incompatible-pointer-types hard errors by default. FALCON's legacy C needs
# them kept as warnings.
CML="$SRC/CMakeLists.txt"
if ! grep -q "THUGSred prep for B210" "$CML"; then
  perl -0pi -e 's{(-std=c99 -D_GNU_SOURCE"\)\n)}{$1  # GCC 14 promotes these legacy-C diagnostics to errors by default; keep them warnings so FALCON'"'"'s C builds (THUGSred prep for B210).\n  set(CMAKE_C_FLAGS "\$\{CMAKE_C_FLAGS\} -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=maybe-uninitialized -fcommon")\n}' "$CML"
fi

# ---- Configure (downloads the pinned srsRAN into build/srsRAN-src) ----------
mkdir -p "$SRC/build"
cd "$SRC/build"
# First configure fetches srsRAN; tolerate the subsequent compile-flag re-detect.
cmake -DENABLE_SRSUE=OFF -DENABLE_SRSENB=OFF -DENABLE_SRSEPC=OFF ../ >/dev/null

SRS="$SRC/build/srsRAN-src"

# ---- Patch 2: bundled fmt missing <array>/<cstdint> (newer libstdc++) -------
FMT="$SRS/lib/include/srsran/srslog/bundled/fmt/core.h"
if ! grep -q "THUGSred: <array>" "$FMT"; then
  perl -0pi -e 's{(#include <vector>\n)}{$1#include <array>   // THUGSred: <array> no longer transitively included\n#include <cstdint>\n}' "$FMT"
fi

# ---- Patch 3: srsRAN blanket -Werror on newer compilers ---------------------
perl -0pi -e 's{\$\{CMAKE_C_FLAGS\} -Werror"}{\$\{CMAKE_C_FLAGS\} -Wno-error"}g; s{\$\{CMAKE_CXX_FLAGS\} -Werror"}{\$\{CMAKE_CXX_FLAGS\} -Wno-error"}g' "$SRS/CMakeLists.txt"

# ---- Patch 4: radio/channel_mapping.h missing <string> ----------------------
CHM="$SRS/lib/include/srsran/radio/channel_mapping.h"
if ! grep -q "THUGSred: <string>" "$CHM"; then
  perl -0pi -e 's{(#include <cinttypes>\n)}{#include <string>   // THUGSred: <string> no longer transitively included\n$1}' "$CHM"
fi

# Re-configure so the srsRAN flag patches take effect, then build.
cmake -DENABLE_SRSUE=OFF -DENABLE_SRSENB=OFF -DENABLE_SRSEPC=OFF ../ >/dev/null
make -j"$JOBS"

echo
echo "Built: $SRC/build/src/LTESniffer"
"$SRC/build/src/LTESniffer" -h 2>&1 | head -3 || true
