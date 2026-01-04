@echo off
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" (
    echo [ERROR] vcvarsall.bat not found at %VCVARS%
    exit /b 1
)

echo [*] Initializing VS environment...
call "%VCVARS%" x64

echo [*] Changing to kernel-driver directory...
cd /d "c:\Users\naman\Desktop\nowhere\kernel-driver"

echo [*] Building driver...
call build_driver.bat

echo [*] Building dumper...
call build_dumper.bat

echo [*] Build sequence complete.
