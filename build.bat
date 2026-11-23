@echo off
setlocal EnableExtensions
pushd "%~dp0"

set "OUT=%~dp0build"
if not exist "%OUT%" mkdir "%OUT%"

where cl >nul 2>nul
if %ERRORLEVEL%==0 goto :have_env

set "VCVARS="
if defined VSINSTALLDIR if exist "%VSINSTALLDIR%VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VSINSTALLDIR%VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set "VSROOT=%%i"
    if defined VSROOT if exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined VCVARS (
    echo [ERROR] 未找到 MSVC 编译环境。请安装 Visual Studio 2022 的“使用 C++ 的桌面开发”组件，
    echo         或从“Developer Command Prompt for VS 2022”中运行本脚本。
    popd
    exit /b 1
)
call "%VCVARS%" x64 >nul

:have_env
echo [1/2] Compiling resources...
rc /nologo /c 65001 /i "%~dp0" /fo "%OUT%\SysbinSystemTools.res" "%~dp0SysbinSystemTools.rc"
if errorlevel 1 goto :failed

echo [2/2] Compiling sources...
cl /nologo /W3 /EHsc /O2 /MT /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /std:c++17 ^
   /Fe:"%OUT%\SysbinSystemTools.exe" /Fo:"%OUT%\\" ^
   "%~dp0Main.cpp" "%~dp0Common.cpp" "%~dp0MemoryPage.cpp" "%~dp0DiskPage.cpp" "%~dp0HostsPage.cpp" ^
   "%OUT%\SysbinSystemTools.res" /link /subsystem:windows /manifest:no
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
