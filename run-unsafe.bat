@echo off
chcp 65001 >nul
title Medfarl AI System - Unsafe Mode

echo ========================================
echo   Medfarl AI System - Повний доступ
echo ========================================
echo.
echo [УВАГА] Запущено режим з повним доступом!
echo Використовуйте з обережністю.
echo.

python main.py --unsafe-full-access --skip-healthcheck

pause
