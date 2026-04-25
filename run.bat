@echo off
setlocal

cd /d "%~dp0"
chcp 65001 >nul
title Medfarl AI System

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if exist ".venv\Scripts\python.exe" (
    set "PYTHON=.venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

echo ========================================
echo   Medfarl AI System - Launch
echo ========================================
echo.

"%PYTHON%" --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found.
    echo Install Python from https://python.org
    pause
    exit /b 1
)

echo [1/2] Checking dependencies...
"%PYTHON%" -m pip show httpx >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing dependencies...
    "%PYTHON%" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Could not install dependencies.
        pause
        exit /b 1
    )
)

echo [2/2] Launching Medfarl AI System...
echo.

"%PYTHON%" main.py %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo Medfarl exited with code %EXIT_CODE%.
)

exit /b %EXIT_CODE%
