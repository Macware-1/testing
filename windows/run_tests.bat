@echo off
:: run_tests.bat — Run the J1939 UDP loopback test suite on Windows
::
:: No USB-CAN adapter or special driver needed.
:: All communication goes over Ethernet: UDP inject (port 4000) + CLOG (port 47808).
::
:: Before running:
::   1. Connect your PC to the gateway over Ethernet.
::   2. Check that GW_IP in Tests\J1939\udp_loopback\config.py matches your gateway.
::   3. Double-click this file.

setlocal

:: ── Check Python ─────────────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found.
    echo   Download from https://www.python.org/  ^(tick "Add to PATH"^).
    pause
    exit /b 1
)

set SCRIPT_DIR=%~dp0
set TEST_DIR=%SCRIPT_DIR%..\Tests\J1939\udp_loopback

echo.
echo ============================================================
echo  CAN-ETH Gateway — J1939 UDP Loopback Test Suite
echo  Tests\J1939\udp_loopback\run_all.py
echo ============================================================
echo.
echo  Edit Tests\J1939\udp_loopback\config.py to set GW_IP
echo  if your gateway IP is not 121.145.35.64
echo.

cd /d "%TEST_DIR%"
python run_all.py %*

echo.
pause
