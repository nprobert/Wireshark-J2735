#!/bin/sh
#
# Master build script for Fedora/RHEL
# Chains: clone -> setup -> compile
#
# Usage:
#   ./rhel-build.sh          # Full build
#   ./rhel-compile.sh        # Rebuild only (after setup is done)
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

./rhel-clone.sh
./rhel-setup.sh
./rhel-compile.sh
