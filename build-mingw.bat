@echo off
setlocal EnableExtensions
pushd "%~dp0"

set "OUT=%~dp0build"
if not exist "%OUT%" mkdir "%OUT%"

where g++ >nul 2>nul
if errorlevel 1 (
    echo [ERROR] g++ not found in PATH. Install MinGW-w64 and add its bin directory to PATH.
    popd
    exit /b 1
)

echo [1/2] Compiling resources with windres...
windres -c 65001 -I . -i SysbinSystemTools.rc -o "%OUT%\sysbin_res.o"
if errorlevel 1 goto :failed

echo [2/2] Compiling sources with g++...
g++ -std=c++17 -municode -mwindows -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601 -O2 -w ^
    Main.cpp Common.cpp MemoryPage.cpp DiskPage.cpp HostsPage.cpp ^
    "%OUT%\sysbin_res.o" ^
    -lcomctl32 -lshell32 -lpsapi -liphlpapi -lws2_32 -lwinhttp ^
    -o "%OUT%\SysbinSystemTools.exe"
if errorlevel 1 goto :failed

echo.
echo [OK] Build succeeded: %OUT%\SysbinSystemTools.exe
popd
exit /b 0

:failed
echo.
echo [FAILED] Build failed.
popd
exit /b 1
