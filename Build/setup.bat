git clone https://gitlab.com/wireshark/wireshark

copy j2735\epan\dissectors\packet-j2735.c wireshark\epan\dissectors
mkdir wireshark\epan\dissectors\asn1\j2735
copy j2735\epan\dissectors\asn1\j2735\*.* wireshark\epan\dissectors\asn1\j2735\

echo "Relative to wireshark\epan\dissectors"
echo "Edit CMakeLists.txt and asn1\CMakeListx.txt to add J2735"
echo "Copy J2735 modified *.asn sources to asn1\j2735"