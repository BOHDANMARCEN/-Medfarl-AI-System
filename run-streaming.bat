@echo off
chcp 65001 >nul
title Medfarl AI System - Interactive Streaming

echo ========================================
echo   Medfarl AI System - Streaming Mode
echo ========================================
echo.
echo Інтерактивний режим - відповіді з'являються в реальному часі!
echo Як Gemini CLI або ChatGPT
echo.

python main.py --stream --model qwen3.5:4b

pause
