#!/bin/sh

SRC=./j2735
DEST=./wireshark/epan/dissectors

cp $SRC/epan/dissectors/packet-j2735.c $DEST

echo "Edit CMakeLists.txt"

vi $DEST/CMakeLists.txt $DEST/asn1/CMakeLists.txt
cp -a $SRC/epan/dissectors/* $DEST

cd $DEST/asn1/j2735
pwd
echo Copy J2735 ASN.1 sources here, edit as needed to make compile
echo Run ./gen.sh
