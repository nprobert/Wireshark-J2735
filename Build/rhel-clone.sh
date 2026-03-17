#!/bin/sh
#
# Clone Wireshark source
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -d wireshark/.git ]; then
	echo "=== Wireshark source already cloned, updating ==="
	cd wireshark
	git pull
else
	echo "=== Cloning Wireshark source ==="
	rm -rf wireshark
	git clone https://gitlab.com/wireshark/wireshark.git
	cd wireshark
fi
