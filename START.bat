@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title VulnScan Pro

rem ---- Ask once for administrator rights, so Nmap/Npcap never prompts again during scans ----
if /i "%~1"=="--elevated" (
    if not "%~2"=="" set "VULNSCAN_PORT=%~2"
    goto :admin_done
)
fltmc >nul 2>&1 && goto :admin_done
powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '--elevated %VULNSCAN_PORT%' -Verb RunAs; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 exit /b 0
echo.
echo  Administrator rights declined: scans run with limited features
echo  (no OS detection or UDP, Npcap may ask for permission).
:admin_done

echo.
echo  ==============================================
echo   VulnScan Pro - network vulnerability scanner
echo  ==============================================
echo.

rem ---- Python ----
set "PY="
where py >nul 2>&1 && py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1 && set "PY=python"
)
if defined PY goto :python_ok

echo  Python is not installed yet.
where winget >nul 2>&1 || goto :python_manual
choice /c YN /m "  Install Python now"
if errorlevel 2 goto :python_manual
winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements
echo.
echo  Done. Please double-click START.bat once more.
pause
exit /b 0

:python_manual
echo  Please install Python from python.org ("Add python.exe to PATH"),
echo  then double-click START.bat again.
start "" https://www.python.org/downloads/
pause
exit /b 1

:python_ok

rem ---- Nmap ----
if exist "C:\Program Files (x86)\Nmap\nmap.exe" set "PATH=%PATH%;C:\Program Files (x86)\Nmap"
if exist "C:\Program Files\Nmap\nmap.exe" set "PATH=%PATH%;C:\Program Files\Nmap"
where nmap >nul 2>&1 && goto :nmap_ok

echo  Nmap is not installed yet. VulnScan Pro needs it to scan.
where winget >nul 2>&1 || goto :nmap_manual
choice /c YN /m "  Install Nmap now"
if errorlevel 2 goto :nmap_ok
winget install --id Insecure.Nmap -e --accept-package-agreements --accept-source-agreements
if exist "C:\Program Files (x86)\Nmap\nmap.exe" set "PATH=%PATH%;C:\Program Files (x86)\Nmap"
if exist "C:\Program Files\Nmap\nmap.exe" set "PATH=%PATH%;C:\Program Files\Nmap"
goto :nmap_ok

:nmap_manual
start "" https://nmap.org/download.html

:nmap_ok

rem ---- Everything else is set up automatically (first start only) ----
if not exist ".venv\Scripts\python.exe" (
    echo  First start: setting everything up, this takes about a minute...
    %PY% -m venv .venv >nul 2>&1
)
fc /b requirements.txt ".venv\requirements.installed" >nul 2>&1 && goto :start
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q --upgrade pip >nul 2>&1
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt >nul 2>&1
if errorlevel 1 (
    echo  Setup failed. Please check your internet connection and start again.
    pause
    exit /b 1
)
copy /y requirements.txt ".venv\requirements.installed" >nul

:start
if not defined VULNSCAN_PORT set "VULNSCAN_PORT=5000"
echo  VulnScan Pro is running at http://127.0.0.1:%VULNSCAN_PORT%
echo  Close this window to stop it.
echo.
start "" /b cmd /c "ping -n 4 127.0.0.1 >nul && start http://127.0.0.1:%VULNSCAN_PORT%"
".venv\Scripts\python.exe" app.py
pause
