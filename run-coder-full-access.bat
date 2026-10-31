@echo off
setlocal
call "%~dp0run.bat" --coder --unsafe-full-access %*
exit /b %ERRORLEVEL%
