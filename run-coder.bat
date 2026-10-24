@echo off
setlocal
call "%~dp0run.bat" --coder %*
exit /b %ERRORLEVEL%
