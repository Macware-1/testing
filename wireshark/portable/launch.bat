@echo off
:: launch.bat — Launch Wireshark with CLOG plugin pre-loaded (portable, no install)
::
:: No admin rights needed. Nothing is written to AppData or the registry.
:: Wireshark home is set to a local folder inside this directory.
::
:: HOW TO USE
:: ──────────
:: Option A — You already have Wireshark installed:
::   Just double-click this file. Done.
::
:: Option B — No Wireshark installed (fully portable):
::   1. Download WiresharkPortable from https://www.wireshark.org/download.html
::      → scroll to "Third-Party Packages" → "Wireshark Portable"
::      OR direct link: https://www.wiresharkportable.com/
::   2. Extract / run the installer and choose THIS folder (wireshark\portable\)
::      as the destination, so WiresharkPortable.exe ends up here.
::   3. Double-click this file.

setlocal

set SCRIPT_DIR=%~dp0

:: ── Set up a portable Wireshark home inside this folder ──────────────────────
set WS_HOME=%SCRIPT_DIR%WiresharkHome
set PLUGIN_DIR=%WS_HOME%\plugins

if not exist "%PLUGIN_DIR%" mkdir "%PLUGIN_DIR%"

:: Copy all Lua plugins and color rules from parent folder
for %%f in ("%SCRIPT_DIR%..\*.lua") do (
    copy /y "%%f" "%PLUGIN_DIR%\" >nul
)
copy /y "%SCRIPT_DIR%..\colorfilters" "%WS_HOME%\" >nul

:: Point Wireshark at our local home (overrides AppData\Wireshark)
set WIRESHARK_HOME=%WS_HOME%

:: ── Find Wireshark executable ─────────────────────────────────────────────────
set WS_EXE=

:: 1. WiresharkPortable next to this script
if exist "%SCRIPT_DIR%WiresharkPortable.exe" set WS_EXE="%SCRIPT_DIR%WiresharkPortable.exe"

:: 2. Wireshark installed in Program Files
if not defined WS_EXE (
    for %%p in (
        "%ProgramFiles%\Wireshark\Wireshark.exe"
        "%ProgramFiles(x86)%\Wireshark\Wireshark.exe"
    ) do if exist %%p set WS_EXE=%%p
)

if not defined WS_EXE (
    echo.
    echo  Wireshark not found.
    echo.
    echo  Option A — Install Wireshark:
    echo    https://www.wireshark.org/download.html
    echo.
    echo  Option B — Download WiresharkPortable and place
    echo    WiresharkPortable.exe in:
    echo    %SCRIPT_DIR%
    echo.
    pause
    exit /b 1
)

echo WIRESHARK_HOME = %WS_HOME%
echo Launching: %WS_EXE%
echo.
start "" %WS_EXE% -k -f "udp port 47808 or udp port 7898"
