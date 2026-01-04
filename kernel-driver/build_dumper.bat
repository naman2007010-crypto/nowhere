@echo off
REM Build the kernel dumper user-mode application
REM Requires Visual Studio

echo [*] Building kernel dumper...

if not exist "build" mkdir build

cl.exe /EHsc /O2 /Fe:build\KernelDumper.exe kernel_dumper.cpp /I. /link advapi32.lib

if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo [+] Build successful: build\KernelDumper.exe
echo.
echo Usage:
echo   1. Load driver with load_driver.bat (as Admin)
echo   2. Launch Roblox
echo   3. Run build\KernelDumper.exe
echo.
pause
