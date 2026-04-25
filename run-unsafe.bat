@echo off
setlocal

title Medfarl AI System - Unsafe Mode
echo ========================================
echo   Medfarl AI System - Повний доступ
echo ========================================
echo.
echo [УВАГА] Запущено режим з повним доступом!
echo Використовуйте з обережністю.
echo.

set "MEDFARL_UNSAFE_FULL_ACCESS=1"
call "%~dp0run.bat" --unsafe-full-access --skip-healthcheck %*

exit /b %ERRORLEVEL%
