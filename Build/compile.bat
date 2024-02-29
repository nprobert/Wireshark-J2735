set PLATFORM=x64
set WIRESHARK_TARGET_PLATFORM=x64
set WIRESHARK_BASE_DIR=%CD%
set WIRESHARK_QT6_PREFIX_PATH=C:\Qt\6.6.2\msvc2019_64
set WIRESHARK_VERSION_EXTRA=-J2735-2024-04

mkdir wsbuild64
cd wsbuild64

cmake -G "Visual Studio 17 2022" -A x64 ..\wireshark

msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln

cd ..
