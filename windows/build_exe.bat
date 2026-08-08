@echo off
:: build_exe.bat — Build standalone Windows .exe files with PyInstaller
::
:: Output goes to:  windows\dist\
::   run_j1939_tests.exe   — J1939 UDP loopback test suite  (console)
::   gateway_demo.exe      — PyQt5 validation GUI            (windowed)
::
:: Run this once; distribute the .exe files — no Python install needed on target PC.
:: No CAN adapter driver required (all communication is UDP/HTTP over Ethernet).

setlocal

:: ── Check PyInstaller ─────────────────────────────────────────────────────────
where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller ...
    pip install pyinstaller>=6.0.0
    if errorlevel 1 ( echo pip install failed. & pause & exit /b 1 )
)

set SCRIPT_DIR=%~dp0
set ROOT=%SCRIPT_DIR%..
set DIST=%SCRIPT_DIR%dist
set BUILD=%SCRIPT_DIR%build_tmp

:: ── Build 1: J1939 UDP loopback test suite ────────────────────────────────────
echo.
echo [1/2] Building run_j1939_tests.exe ...
pyinstaller ^
    --onefile ^
    --console ^
    --name run_j1939_tests ^
    --distpath "%DIST%" ^
    --workpath "%BUILD%" ^
    --specpath "%BUILD%" ^
    --paths "%ROOT%\Tests\J1939\udp_loopback" ^
    --paths "%ROOT%\Tests\J1939" ^
    --add-data "%ROOT%\Tests\J1939\udp_loopback\config.py;." ^
    "%ROOT%\Tests\J1939\udp_loopback\run_all.py"

if errorlevel 1 (
    echo FAILED: run_j1939_tests.exe build error.
    goto :end
)
echo OK → dist\run_j1939_tests.exe

:: ── Build 2: PyQt5 validation GUI ────────────────────────────────────────────
echo.
echo [2/2] Building gateway_demo.exe ...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name gateway_demo ^
    --distpath "%DIST%" ^
    --workpath "%BUILD%" ^
    --specpath "%BUILD%" ^
    --paths "%ROOT%\validation" ^
    --paths "%ROOT%\validation\demo" ^
    --paths "%ROOT%\validation\sdk" ^
    --collect-all PyQt5 ^
    --collect-all pyqtgraph ^
    --hidden-import requests ^
    "%ROOT%\validation\demo\main.py"

if errorlevel 1 (
    echo FAILED: gateway_demo.exe build error.
    goto :end
)
echo OK → dist\gateway_demo.exe

:: ── Done ──────────────────────────────────────────────────────────────────────
echo.
echo ============================================================
echo  Build complete.  Executables are in:
echo    %DIST%\run_j1939_tests.exe
echo    %DIST%\gateway_demo.exe
echo.
echo  Both talk to the gateway over Ethernet — no drivers needed.
echo  Edit GW_IP in config.py before building if your gateway IP
echo  differs from 121.145.35.64.
echo ============================================================

:end
if exist "%BUILD%" rmdir /s /q "%BUILD%"
pause
