set PLATFORM=x64
set WIRESHARK_TARGET_PLATFORM=x64
set WIRESHARK_BASE_DIR=D:\Wireshark-J2735\Build
set WIRESHARK_QT6_PREFIX_PATH=C:\Qt\6.8.1\msvc2022_64
set WIRESHARK_VERSION_EXTRA=-J2735-20250110

mkdir wsbuild64
cd wsbuild64

cmake -G "Visual Studio 17 2022" -A x64 ..\wireshark

msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln

cd ..
