#!/bin/sh

export WIRESHARK_VERSION_EXTRA=-J2735-20240916

rm *.deb

cd wireshark
ln -fs packaging/debian
export DEB_BUILD_OPTIONS="nocheck"
dpkg-buildpackage -b -d -uc -us -jauto

