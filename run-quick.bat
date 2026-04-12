@echo off
chcp 65001 >nul
title Medfarl AI System - Швидкий запуск

echo ========================================
echo   Medfarl AI System - Швидкий запуск
echo ========================================
echo.

REM Пропускає перевірку Ollama для швидкого старту
python main.py --skip-healthcheck

pause
