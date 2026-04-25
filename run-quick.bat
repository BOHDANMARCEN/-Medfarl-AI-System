@echo off
setlocal

title Medfarl AI System - Швидкий запуск
call "%~dp0run.bat" --skip-healthcheck %*

exit /b %ERRORLEVEL%
