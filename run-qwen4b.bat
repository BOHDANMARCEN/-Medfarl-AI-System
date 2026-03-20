@echo off
setlocal

set "MEDFARL_MODEL=qwen3.5:4b"
call "%~dp0run.bat" %*

exit /b %ERRORLEVEL%
