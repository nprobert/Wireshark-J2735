git clone https://gitlab.com/wireshark/wireshark

copy j2735\epan\dissectors\packet-j2735.c wireshark\epan\dissectors
mkdir wireshark\epan\dissectors\asn1\j2735
copy j2735\epan\dissectors\asn1\j2735\*.* wireshark\epan\dissectors\asn1\j2735\
echo "Copied J2735 modified *.asn sources to asn1\j2735 done!"

echo "Relative to wireshark\epan\dissectors"
echo ">>> Edit CMakeLists.txt and asn1\CMakeLists.txt to add J2735"
cd wireshark\epan\dissectors
"C:\Program Files\Notepad++\notepad++.exe" CMakeLists.txt asn1\CmakeLists.txt 
