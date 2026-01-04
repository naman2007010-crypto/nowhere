@echo off
setlocal enabledelayedexpansion

echo [NOWHERE] Starting Build Process...

:: 1. Check for FastColoredTextBox.dll
if not exist "lib\FastColoredTextBox.dll" (
    echo [ERROR] FastColoredTextBox.dll not found in lib folder!
    exit /b 1
)

:: 2. Find Visual Studio
set "VISHUAL_STUDIO_PATH="
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do (
    set "VISHUAL_STUDIO_PATH=%%i"
)

if "%VISHUAL_STUDIO_PATH%"=="" (
    echo [ERROR] Visual Studio not found!
    pause
    exit /b 1
)

echo [INFO] Found Visual Studio at: %VISHUAL_STUDIO_PATH%

:: 3. Setup Environment
call "%VISHUAL_STUDIO_PATH%\Common7\Tools\VsDevCmd.bat"

:: 4. Build C++ Engine
echo [INFO] Building XenoEngine (x64 Release)...
msbuild "xeno-engine\XenoEngine.vcxproj" /p:Configuration=Release /p:Platform=x64
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build XenoEngine!
    pause
    exit /b 1
)

:: 5. Copy Engine to Output
echo [INFO] Copying XenoEngine.dll...
if not exist "bin\Release" mkdir "bin\Release"
copy /Y "xeno-engine\bin\Release\XenoEngine.dll" "bin\Release\XenoEngine.dll"

:: 6. Build C# Injector
echo [INFO] Building NowhereInjector (x64 Release)...
msbuild "NowhereInjector1.csproj" /p:Configuration=Release /p:Platform=x64
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to build Injector!
    pause
    exit /b 1
)

echo [SUCCESS] Build Complete! Run bin\Release\NowhereInjector1.exe
pause
