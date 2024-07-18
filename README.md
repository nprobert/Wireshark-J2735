# Wireshark-J2735
**Wireshark custom build with DSRC (IEEE 802.11p, WSMP and 1609.2) support and SAE J2735 Dissector**
1. Wireshark builds have moved to Ubuntu 24.04, Windows 10/11 and 4.3.X development branch, 64-bit only
2. Wireshark 3.0.0 added support for EU ITS, WSMP and 1609.2 thanks to ETSI and Wireshark Devs
3. Supports the IEEE 1609.2, 1609.3-WSMP and SAE J2735-2023 standards
4. IEEE 1609.3 is not fully supported and 1609.4 will probably never be supported

**C-V2X**
1. Does not support C-V2X cellular stack yet, but most C-V2X OBU vendors will output a special packet:
2. Sets destination MAC address to all ffs (broadcast)
3. Sets source MAC address to all 0s for RX packets and all FFs for TX packets
4. Non-IP Type Header of Ethertype 0x88DC followed by WSMP layer which contains the 1609.2 layer and J2735 data

**Issues**
1. The **Recommended** J2735-2024 release is fully backwards compatible with J2735-2020.
2. **Do not use J2735-2022 due to bugs**, use the J2735-2024 release when available
3. The J2735-2023 release is backwards incompatible with J2735-2020 using the BSM frame VehicleData, which is not specified in J2945/1.

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
2. The files under Sources go into the Wireshark root directory "wireshark"
3. Please diff the CMakeLists.txt files so that you don't break your build
4. The SAE J2735 ASN.1 files go into epan/dissectors/asn1/j2735

**Issues**
1. Does not dissect 3rd party regional extensions to J2735 as this required modified ASN.1 to compiled with

**I cannot release the ASN.1 file for SAE J2735 because it is copyrighted material!  However the J2735 documentation and J2945 ASN.1 are free from SAE here:**
1. https://www.sae.org/standards/content/j2735_202309/
2. https://www.sae.org/standards/content/j2735ASN_202309/
