git clone https://gitlab.com/wireshark/wireshark

copy j2735\epan\dissectors\packet-j2735.c wireshark\epan\dissectors
mkdir wireshark\epan\dissectors\asn1\j2735
copy j2735\epan\dissectors\asn1\j2735\*.* wireshark\epan\dissectors\asn1\j2735\
echo "Copied J2735 modified *.asn sources to asn1\j2735 done!"
copy ieee1609dot3\epan\dissectors\packet-wsa.c wireshark\epan\dissectors
echo "Copied IEEE 1609.3 WSA dissector packet-wsa.c"

echo "Relative to wireshark\epan\dissectors"
echo ">>> Edit CMakeLists.txt and asn1\CMakeLists.txt to add J2735"
echo ">>> Also add packet-wsa.c before packet-wsmp.c in CMakeLists.txt"
cd wireshark\epan\dissectors
"C:\Program Files\Notepad++\notepad++.exe" CMakeLists.txt asn1\CmakeLists.txt 
