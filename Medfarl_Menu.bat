@echo off
chcp 65001 >nul
title Medfarl AI System - Menu

cd /d "%~dp0"

:menu
cls
echo ========================================
echo     Medfarl AI System - Launch Menu
echo ========================================
echo.
echo  AVAILABLE MODELS:
echo  1. qwen3.5:4b         ^(3.4 GB - fast^)
echo  2. qwen3.5:9b         ^(6.6 GB - quality^)
echo  3. llama3.2:3b        ^(2.0 GB - light^)
echo  4. gemma-abliterated  ^(7.3 GB^)
echo  5. gpt-oss-20b        ^(11 GB - powerful^)
echo  6. qwen2.5-1m:14b     ^(9.0 GB - large context^)
echo  7. qwen3:14b          ^(9.0 GB - uncensored^)
echo  8. Cloud models       ^(gemini, kimi, deepseek, qwen-coder^)
echo.
echo  ACTIONS:
echo  10. Default launch ^(Streaming, qwen3.5:9b^)
echo  11. Quick launch ^(Streaming, skip healthcheck^)
echo  12. Full access mode ^(Unsafe^)
echo  13. Healthcheck
echo  14. List models
echo  15. Benchmark ^(compare models^)
echo  16. INTERACTIVE MODE ^(Streaming like Gemini CLI, qwen3.5:9b^)
echo  17. Exit
echo.
echo ========================================

set /p choice="Choose an option (1-17): "

if "%choice%"=="1" goto model_qwen_4b
if "%choice%"=="2" goto model_qwen_9b
if "%choice%"=="3" goto model_llama_3b
if "%choice%"=="4" goto model_gemma
if "%choice%"=="5" goto model_gpt_20b
if "%choice%"=="6" goto model_qwen25_14b
if "%choice%"=="7" goto model_qwen3_14b
if "%choice%"=="8" goto cloud_models
if "%choice%"=="10" goto normal
if "%choice%"=="11" goto quick
if "%choice%"=="12" goto unsafe
if "%choice%"=="13" goto healthcheck
if "%choice%"=="14" goto listmodels
if "%choice%"=="15" goto benchmark
if "%choice%"=="16" goto streaming
if "%choice%"=="17" goto end

echo Invalid choice!
pause
goto menu

:model_qwen_4b
echo.
echo Launching with qwen3.5:4b...
call "%~dp0run.bat" --model qwen3.5:4b
goto menu

:model_qwen_9b
echo.
echo Launching with qwen3.5:9b...
call "%~dp0run.bat" --model qwen3.5:9b
goto menu

:model_llama_3b
echo.
echo Launching with llama3.2:3b...
call "%~dp0run.bat" --model llama3.2:3b
goto menu

:model_gemma
echo.
echo Launching with gemma-abliterated...
call "%~dp0run.bat" --model gemma-abliterated
goto menu

:model_gpt_20b
echo.
echo Launching with gpt-oss-20b...
call "%~dp0run.bat" --model gpt-oss-20b --timeout 240
goto menu

:model_qwen25_14b
echo.
echo Launching with qwen2.5-1m:14b...
call "%~dp0run.bat" --model huihui_ai/qwen2.5-1m-abliterated:14b --timeout 240
goto menu

:model_qwen3_14b
echo.
echo Launching with qwen3:14b ^(uncensored^)...
call "%~dp0run.bat" --model huihui_ai/qwen3-abliterated:14b --timeout 240
goto menu

:cloud_models
echo.
echo Cloud models require MEDFARL_LLM_URL setup.
echo Try a local model ^(1-7^) or use option 11.
pause
goto menu

:normal
echo.
echo Starting default mode ^(Streaming + qwen3.5:9b^) ...
call "%~dp0run.bat"
goto menu

:quick
echo.
echo Starting quick mode ^(Streaming, skip healthcheck^) ...
call "%~dp0run-quick.bat"
goto menu

:unsafe
echo.
echo Starting full access mode...
call "%~dp0run-unsafe.bat"
goto menu

:healthcheck
echo.
echo Running healthcheck...
call "%~dp0run.bat" --healthcheck
goto menu

:listmodels
echo.
echo Listing available models...
call "%~dp0run.bat" --list-models
goto menu

:benchmark
echo.
echo Benchmarking models ^(qwen3.5:4b, qwen3.5:9b, llama3.2:3b^) ...
call "%~dp0run.bat" --benchmark-models qwen3.5:4b qwen3.5:9b llama3.2:3b
goto menu

:streaming
echo.
echo Starting interactive streaming mode ^(qwen3.5:9b^) ...
call "%~dp0run-streaming.bat"
goto menu

:end
echo.
echo Goodbye!
exit /b 0
