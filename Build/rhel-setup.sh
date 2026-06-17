#!/bin/sh
#
# Install Fedora/RHEL build dependencies and copy J2735 dissector files
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Installing build dependencies ==="
if [ -f wireshark/tools/rpm-setup.sh ]; then
	sudo wireshark/tools/rpm-setup.sh --install-optional
else
	echo "ERROR: wireshark source not found. Run rhel-clone.sh first."
	exit 1
fi

echo ""
echo "=== Copying J2735 dissector files ==="

SRC=./j2735
DEST=./wireshark/epan/dissectors

# Copy pre-generated dissector source
cp "$SRC/epan/dissectors/packet-j2735.c" "$DEST/"

# Copy ASN.1 sources and build config
cp -a "$SRC/epan/dissectors/asn1/j2735" "$DEST/asn1/"

echo ""
echo "=== Adding j2735 to CMake build files ==="

# Add packet-j2735.c to dissectors CMakeLists.txt (after packet-its.c, alphabetical order)
if ! grep -q 'packet-j2735\.c' "$DEST/CMakeLists.txt"; then
	sed -i '/packet-its\.c/a\\t${CMAKE_CURRENT_SOURCE_DIR}/packet-j2735.c' "$DEST/CMakeLists.txt"
	echo "Added packet-j2735.c to $DEST/CMakeLists.txt"
else
	echo "packet-j2735.c already in $DEST/CMakeLists.txt"
fi

# NOTE: We intentionally do NOT add j2735 to asn1/CMakeLists.txt.
# The J2735-2024 ASN files use Information Object Class syntax (&id, &Type, CLASS)
# which asn2wrs.py cannot parse. Instead, we use the pre-generated packet-j2735.c
# that is already compiled via the dissectors CMakeLists.txt entry above.

echo ""
echo "=== Setup complete ==="
