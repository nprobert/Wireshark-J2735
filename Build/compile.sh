#!/bin/sh

export WIRESHARK_VERSION_EXTRA=-J2735-2024-04

rm -rf wireshark-ninja
mkdir -p wireshark-ninja
cd wireshark-ninja

# Assumes your source directory is named "wireshark".
cmake -G Ninja ../wireshark
ninja		# (or cmake --build .)

