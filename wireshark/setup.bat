@echo off
:: setup.bat — Install CLOG Wireshark plugin (Windows)
::
:: Copies clog_dissector.lua and colorfilters into your personal Wireshark
:: configuration folder so they are available the next time Wireshark starts.
::
:: Requires Wireshark to already be installed.
:: For portable Wireshark (no install): use portable\launch.bat instead.

setlocal

set SCRIPT_DIR=%~dp0
set WS_PROFILE=%APPDATA%\Wireshark

:: ── Check Wireshark is installed ──────────────────────────────────────────────
set WS_EXE=
for %%p in (
    "%ProgramFiles%\Wireshark\Wireshark.exe"
    "%ProgramFiles(x86)%\Wireshark\Wireshark.exe"
) do if exist %%p set WS_EXE=%%p

if not defined WS_EXE (
    echo Wireshark does not appear to be installed.
    echo   Download from https://www.wireshark.org/
    echo.
    echo For a portable setup without installing Wireshark use:
    echo   wireshark\portable\launch.bat
    pause
    exit /b 1
)
echo Found Wireshark: %WS_EXE%

:: ── Install Lua plugins ───────────────────────────────────────────────────────
set PLUGIN_DIR=%WS_PROFILE%\plugins
if not exist "%PLUGIN_DIR%" mkdir "%PLUGIN_DIR%"

for %%f in ("%SCRIPT_DIR%*.lua") do (
    copy /y "%%f" "%PLUGIN_DIR%\" >nul
    echo Installed: %PLUGIN_DIR%\%%~nxf
)

:: ── Install color rules ───────────────────────────────────────────────────────
copy /y "%SCRIPT_DIR%colorfilters" "%WS_PROFILE%\" >nul
echo Installed: %WS_PROFILE%\colorfilters

:: ── Done ──────────────────────────────────────────────────────────────────────
echo.
echo ============================================================
echo  CLOG plugin installed.
echo.
echo  In Wireshark: Analyze → Reload Lua Plugins  (Ctrl+Shift+L)
echo  Or just restart Wireshark.
echo.
echo  Capture filter:   udp port 47808 or udp port 7898
echo  CLOG display filter:   clog
echo  Status display filter: gwstat
echo ============================================================
pause
