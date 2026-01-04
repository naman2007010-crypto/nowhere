@echo off
REM ============================================================================
REM Nowhere Kernel Driver Build Script
REM Requires: Windows Driver Kit (WDK) installed
REM ============================================================================

echo ============================================
echo    Nowhere Kernel Driver Build
echo ============================================

REM Check for WDK paths
set "WDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WDK_BIN=%WDK_PATH%\bin\10.0.26100.0\x64"
set "WDK_INC=%WDK_PATH%\Include\10.0.26100.0"
set "WDK_LIB=%WDK_PATH%\Lib\10.0.26100.0"
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community"

if not exist "%WDK_PATH%" (
    echo [ERROR] WDK not found at "%WDK_PATH%"
    echo Please install Windows Driver Kit from:
    echo https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    pause
    exit /b 1
)

REM Find cl.exe from Visual Studio
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] cl.exe not found in PATH
    echo Please run this from a Visual Studio Developer Command Prompt
    echo Or run vcvarsall.bat x64
    pause
    exit /b 1
)

echo [*] WDK found at: "%WDK_PATH%"
echo [*] Building kernel driver...

REM Create output directory
if not exist "build" mkdir build

REM Compile driver
cl.exe /c /Zi /nologo /W3 /WX- /Ox /Oi /GL ^
    /D _AMD64_ /D _WIN64 /D NTDDI_VERSION=0x0A00000B /D _KERNEL_MODE ^
    /GF /Gm- /EHs-c- /GS- /Gy /fp:precise ^
    /Zc:wchar_t /Zc:forScope /Zc:inline ^
    /GR- /Fo"build\\" /Fd"build\driver.pdb" ^
    /I"%WDK_INC%\km" ^
    /I"%WDK_INC%\shared" ^
    /kernel ^
    driver.c

if %errorlevel% neq 0 (
    echo [ERROR] Compilation failed!
    pause
    exit /b 1
)

REM Link driver
link.exe /OUT:"build\NowhereDumper.sys" /NOLOGO /INCREMENTAL:NO ^
    /LTCG /MANIFEST:NO /DEBUG ^
    /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry ^
    /NODEFAULTLIB ^
    /LIBPATH:"%WDK_LIB%\km\x64" ^
    "build\driver.obj" ^
    ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowFastFailK.lib

if %errorlevel% neq 0 (
    echo [ERROR] Linking failed!
    pause
    exit /b 1
)

echo.
echo ============================================
echo [SUCCESS] Driver built: build\NowhereDumper.sys
echo ============================================
echo.
echo To load the driver:
echo   1. Enable test signing: bcdedit /set testsigning on
echo   2. Reboot
echo   3. Run load_driver.bat as Administrator
echo.
pause
