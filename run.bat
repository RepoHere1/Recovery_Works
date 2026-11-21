@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Recovery Works - Launcher

rem ── Pick the first interpreter that has the FULL dependency stack ──
rem (bip_utils needs coincurve wheels: available on 3.12, not 3.14/3.15)
set "CHECK=import requests, cryptography, bip_utils, mnemonic, base58, solders"
set "PY="

py -3.12 -c "%CHECK%" >nul 2>&1 && set "PY=py -3.12"
if not defined PY py -3.14 -c "%CHECK%" >nul 2>&1 && set "PY=py -3.14"
if not defined PY python -c "%CHECK%" >nul 2>&1 && set "PY=python"

if not defined PY (
    echo [launcher] Dependencies missing - installing for Python 3.12 ...
    py -3.12 -m pip install -r requirements.txt
    py -3.12 -c "%CHECK%" >nul 2>&1 && set "PY=py -3.12"
)

if not defined PY (
    echo [launcher] WARNING: full stack unavailable - falling back to default python.
    set "PY=python"
)

echo [launcher] Using: %PY%
%PY% Recovery_Works.py
if errorlevel 1 (
    echo.
    echo [launcher] App exited with an error - window will stay open.
    pause
)
