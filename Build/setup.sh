#!/bin/sh

echo "Installing package dependencies"
sudo wireshark/tools/debian-setup.sh --install-optional --install-deb-deps

SRC=./j2735
DEST=./wireshark/epan/dissectors

echo Copy J2735 ASN.1 sources here, edit as needed to make compile
cp $SRC/epan/dissectors/packet-j2735.c $DEST

echo "Edit CMakeLists.txt"

vi $DEST/CMakeLists.txt $DEST/asn1/CMakeLists.txt
cp -a $SRC/epan/dissectors/* $DEST

cd $DEST/asn1/j2735
pwd
echo Run ./gen.sh
./gen.sh
