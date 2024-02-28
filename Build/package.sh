#!/bin/sh

export WIRESHARK_VERSION_EXTRA=-J2735-2024-04

rm *.deb

cd wireshark
ln -fs packaging/debian
export DEB_BUILD_OPTIONS="nocheck"
dpkg-buildpackage -b -d -uc -us -jauto

