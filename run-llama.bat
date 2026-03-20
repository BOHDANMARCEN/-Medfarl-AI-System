@echo off
setlocal

set "MEDFARL_MODEL=llama3.2:3b"
call "%~dp0run.bat" %*

exit /b %ERRORLEVEL%
