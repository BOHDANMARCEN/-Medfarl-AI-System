@echo off
chcp 65001 >nul
title Medfarl AI System

echo ========================================
echo   Medfarl AI System - Запуск
echo ========================================
echo.

REM Перевірка чи встановлений Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ПОМИЛКА] Python не знайдено!
    echo Встановіть Python з https://python.org
    pause
    exit /b 1
)

REM Перевірка чи встановлені залежності
echo [1/3] Перевірка залежностей...
pip show httpx >nul 2>&1
if errorlevel 1 (
    echo [ІНФО] Встановлення залежностей...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ПОМИЛКА] Не вдалося встановити залежності!
        pause
        exit /b 1
    )
)

echo [2/3] Перевірка Ollama...
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo [ПОПЕРЕДЖЕННЯ] Ollama не запущено або не встановлено!
    echo.
    echo Для встановлення Ollama: https://ollama.ai
    echo Або запустіть з параметром --skip-healthcheck
    echo.
    pause
)

echo [3/3] Запуск Medfarl AI System...
echo.
python main.py

pause
