#!/bin/sh
#
# Master build script for Debian/Ubuntu
# Chains: clone -> setup -> compile
#
# Usage:
#   ./ubuntu-build.sh          # Full build
#   ./ubuntu-compile.sh        # Rebuild only (after setup is done)
#
# Prerequisites:
#   - git, curl, cmake, ninja-build, gcc, gcc-c++
#   - Internet access (clones Wireshark, downloads Lua 5.3)
#   - sudo access (installs build dependencies via dnf)
#
# After build completes, install with:
#   cd wireshark-ninja && sudo ninja install && sudo ldconfig
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

./ubuntu-clone.sh
./ubuntu-setup.sh
./ubuntu-compile.sh
