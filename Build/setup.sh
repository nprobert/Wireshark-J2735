#!/bin/sh

SRC=./j2735
DEST=./wireshark/epan/dissectors

cp $SRC/epan/dissectors/packet-j2735.c $DEST
cp -r $SRC/epan/dissectors/asn1/j2735 $DEST/asn1/

echo "Edit CMakeLists.txt"

vi $DEST/CMakeLists.txt $DEST/asn1/CMakeLists.txt

cd $DEST/asn1/j2735
./gen.sh

#cd wireshark
#git add packet-j2735.c asn1/j2735
#git commit -am "J2735 Added to Wireshark"
