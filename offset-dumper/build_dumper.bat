@echo off
setlocal

:: Find Visual Studio
set "VS_PATH="
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_PATH=%%i"
)

if "%VS_PATH%"=="" (
    echo [ERROR] Visual Studio not found!
    exit /b 1
)

:: Set up environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

echo [INFO] Building Offset Dumper...
cl.exe /EHsc /std:c++17 /O2 main.cpp /Fo:offset_dumper.obj /Fe:OffsetDumper.exe user32.lib kernel32.lib psapi.lib advapi32.lib

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] OffsetDumper.exe built successfully!
) else (
    echo [ERROR] Build failed.
)
