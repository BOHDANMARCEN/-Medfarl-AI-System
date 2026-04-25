@echo off
setlocal

title Medfarl AI System - Interactive Streaming
echo ========================================
echo   Medfarl AI System - Streaming Mode
echo ========================================
echo.
echo Інтерактивний режим - відповіді з'являються в реальному часі!
echo Як Gemini CLI або ChatGPT
echo.

call "%~dp0run.bat" --stream --model qwen3.5:4b %*

exit /b %ERRORLEVEL%
