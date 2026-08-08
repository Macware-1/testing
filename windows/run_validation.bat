@echo off
:: run_validation.bat — Launch the PyQt5 validation GUI on Windows
::
:: No special drivers needed — talks to the gateway over HTTP + UDP.
::
:: Before running:
::   1. Connect your PC to the gateway over Ethernet.
::   2. Check that GW_IP in validation\j1939\config.py matches your gateway.
::   3. Install Python 3.10+ from https://www.python.org/  (tick "Add to PATH")
::   4. Double-click this file.

setlocal

:: ── Check Python ─────────────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found.
    echo   Download from https://www.python.org/  ^(tick "Add to PATH"^).
    pause
    exit /b 1
)

:: ── Install PyQt5 and dependencies if missing ─────────────────────────────────
python -c "import PyQt5" >nul 2>&1
if errorlevel 1 (
    echo Installing Python dependencies ...
    pip install requests>=2.31.0 PyQt5>=5.15.0 pyqtgraph>=0.13.0
    if errorlevel 1 ( echo pip install failed. & pause & exit /b 1 )
)

set SCRIPT_DIR=%~dp0
set DEMO_DIR=%SCRIPT_DIR%..\validation\demo

echo.
echo Starting CAN-ETH Gateway Demo GUI ...
echo.
echo Edit validation\j1939\config.py to set GW_IP
echo if your gateway IP is not 121.145.35.64
echo.

cd /d "%DEMO_DIR%"
python main.py %*

if errorlevel 1 (
    echo.
    echo Application exited with an error.
    pause
)
