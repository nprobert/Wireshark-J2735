#!/bin/sh
#
# Build Wireshark with J2735 support on Fedora/RHEL
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

export WIRESHARK_VERSION_EXTRA=-J2735-20240916

# Build Lua 5.3 if not already present.
# Fedora 43+ ships Lua 5.4 which has breaking API changes that Wireshark
# (which requires Lua >= 5.3 but < 5.4) cannot compile against.
LUA_PREFIX="$SCRIPT_DIR/lua5.3"
if [ ! -f "$LUA_PREFIX/lib/liblua.a" ]; then
	echo "=== Building Lua 5.3 (required by Wireshark) ==="
	LUA_BUILD=$(mktemp -d)
	curl -fsSL https://www.lua.org/ftp/lua-5.3.6.tar.gz | tar xz -C "$LUA_BUILD"
	make -C "$LUA_BUILD/lua-5.3.6" linux MYCFLAGS="-fPIC" -j$(nproc)
	make -C "$LUA_BUILD/lua-5.3.6" install INSTALL_TOP="$LUA_PREFIX"
	rm -rf "$LUA_BUILD"
	echo "Lua 5.3.6 installed to $LUA_PREFIX"
fi

rm -rf wireshark-ninja
mkdir -p wireshark-ninja
cd wireshark-ninja

echo "=== Configuring with CMake ==="
cmake -G Ninja \
	-DLUA_INCLUDE_DIR="$LUA_PREFIX/include" \
	-DLUA_LIBRARY="$LUA_PREFIX/lib/liblua.a" \
	../wireshark

echo "=== Building with Ninja ==="
ninja -j$(nproc)

echo ""
echo "=== Build complete ==="
echo "To install system-wide, run:"
echo "  cd $SCRIPT_DIR/wireshark-ninja && sudo ninja install && sudo ldconfig"


