# Wireshark-J2735
**Wireshark custom build with DSRC (IEEE 802.11p, WSMP and 1609.2) support and SAE J2735 Dissector**

1. Wireshark builds have moved to Ubuntu 22.04, Windows 10/11 and 4.1.X development branch, 64-bit only
2. Wireshark 3.0.0 added support for EU ITS, WSMP and 1609.2 thanks to ETSI and Wireshark Devs
3. **Do not use J2735-2022 due to bugs**
4. Supports the IEEE 1609.2, 1609.3-WSMP and SAE J2735-2023 standards
5. IEEE 1609.3 is not fully supported and 1609.4 will probably never be supported
6. Does not support C-V2X cellular stack yet
7. Most C-V2X OBU vendors will output a UDP packet with Non-IP Type Header of 0x88DC followed by WSMP layer

**Releases**
Use latest release build only, using SAE J2735-2023 and above

**Linux (Debian/Ubuntu) Packages**
1. dpkg -i *.deb
2. apt-get -f install

For DIY folks, the gory details for building Wireshark on Linux is here: https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcBuildFirstTime.html#_building_on_unix

**Windows Installer** (don't install over existing production release)
1. Run install.bat to combine split files and run installer

For DIY folks, the build for Windows is here: https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html

**Sources**
1. git clone https://code.wireshark.org/review/wireshark
2. The files under Sources go into the Wireshark root directory
3. Please diff the CMakeLists.txt files so that you don't break your build

**Issues**
1. Does not dissect 3rd party regional extensions to J2735 as this required modified ASN to compiled with

**I cannot release the ASN.1 file for SAE J2735 because it is copyrighted material!  However the J2735 and J2945 ASN.1 and documentation are now free from SAE!**
