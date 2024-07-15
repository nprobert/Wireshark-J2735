set PLATFORM=x64
set WIRESHARK_TARGET_PLATFORM=x64
set WIRESHARK_BASE_DIR=%CD%
set WIRESHARK_QT6_PREFIX_PATH=C:\Qt\6.7.0\msvc2019_64
set WIRESHARK_VERSION_EXTRA=-J2735-20240528

mkdir wsbuild64
cd wsbuild64

msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis_prep.vcxproj
msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis.vcxproj

cd ..
