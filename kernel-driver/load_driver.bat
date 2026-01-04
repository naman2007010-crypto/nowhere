@echo off
REM ============================================================================
REM Driver Loader/Unloader Script
REM Run as Administrator!
REM ============================================================================

echo ============================================
echo    Nowhere Driver Loader
echo ============================================

REM Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run as Administrator!
    pause
    exit /b 1
)

set DRIVER_NAME=NowhereDumper
set DRIVER_PATH=%~dp0build\NowhereDumper.sys

if not exist "%DRIVER_PATH%" (
    echo [ERROR] Driver not found: %DRIVER_PATH%
    echo Please build the driver first with build_driver.bat
    pause
    exit /b 1
)

echo.
echo [1] Load driver
echo [2] Unload driver
echo [3] Reload driver (unload + load)
echo [4] Check driver status
echo [5] Exit
echo.
set /p choice="Select option: "

if "%choice%"=="1" goto load
if "%choice%"=="2" goto unload
if "%choice%"=="3" goto reload
if "%choice%"=="4" goto status
if "%choice%"=="5" exit /b 0

echo Invalid option
goto :eof

:load
echo [*] Loading driver...
sc create %DRIVER_NAME% type= kernel binPath= "%DRIVER_PATH%"
sc start %DRIVER_NAME%
if %errorlevel% equ 0 (
    echo [SUCCESS] Driver loaded!
) else (
    echo [ERROR] Failed to load driver. Error code: %errorlevel%
    echo.
    echo Common issues:
    echo   - Test signing not enabled (bcdedit /set testsigning on)
    echo   - Driver not signed
    echo   - Secure Boot enabled (disable in BIOS)
)
goto end

:unload
echo [*] Unloading driver...
sc stop %DRIVER_NAME%
sc delete %DRIVER_NAME%
echo [*] Driver unloaded
goto end

:reload
echo [*] Reloading driver...
sc stop %DRIVER_NAME% 2>nul
sc delete %DRIVER_NAME% 2>nul
timeout /t 1 >nul
sc create %DRIVER_NAME% type= kernel binPath= "%DRIVER_PATH%"
sc start %DRIVER_NAME%
if %errorlevel% equ 0 (
    echo [SUCCESS] Driver reloaded!
) else (
    echo [ERROR] Failed to reload driver
)
goto end

:status
echo [*] Driver status:
sc query %DRIVER_NAME%
goto end

:end
pause
