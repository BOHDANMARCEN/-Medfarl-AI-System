@echo off
chcp 65001 >nul
title Medfarl AI System - Меню

cd /d "%~dp0"

:menu
cls
echo ========================================
echo     Medfarl AI System - Меню запуску
echo ========================================
echo.
echo  ДОСТУПНІ МОДЕЛІ:
echo  1. qwen3.5:4b         (3.4 GB - швидка)
echo  2. qwen3.5:9b         (6.6 GB - якісна)
echo  3. llama3.2:3b        (2.0 GB - легка)
echo  4. gemma-abliterated  (7.3 GB)
echo  5. gpt-oss-20b        (11 GB - потужна)
echo  6. qwen2.5-1m:14b     (9.0 GB - великий контекст)
echo  7. qwen3:14b          (9.0 GB - без цензури)
echo  8. Cloud моделі       (gemini, kimi, deepseek, qwen-coder)
echo.
echo  ЗАПУСК:
echo  10. Звичайний запуск (qwen3.5:4b)
echo  11. Швидкий запуск (без перевірки)
echo  12. Режим повного доступу (Unsafe)
echo  13. Перевірка здоров'я
echo  14. Список моделей
echo  15. Бенчмарк (порівняння моделей)
echo  16. ІНТЕРАКТИВНИЙ РЕЖИМ (Streaming як Gemini CLI)
echo  17. Вихід
echo.
echo ========================================

set /p choice="Оберіть опцію (1-17): "

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

echo Невірний вибір!
pause
goto menu

:model_qwen_4b
echo.
echo Запуск з моделлю qwen3.5:4b...
call "%~dp0run.bat" --model qwen3.5:4b
goto menu

:model_qwen_9b
echo.
echo Запуск з моделлю qwen3.5:9b...
call "%~dp0run.bat" --model qwen3.5:9b
goto menu

:model_llama_3b
echo.
echo Запуск з моделлю llama3.2:3b...
call "%~dp0run.bat" --model llama3.2:3b
goto menu

:model_gemma
echo.
echo Запуск з моделлю gemma-abliterated...
call "%~dp0run.bat" --model gemma-abliterated
goto menu

:model_gpt_20b
echo.
echo Запуск з моделлю gpt-oss-20b...
call "%~dp0run.bat" --model gpt-oss-20b --timeout 240
goto menu

:model_qwen25_14b
echo.
echo Запуск з моделлю qwen2.5-1m:14b...
call "%~dp0run.bat" --model huihui_ai/qwen2.5-1m-abliterated:14b --timeout 240
goto menu

:model_qwen3_14b
echo.
echo Запуск з моделлю qwen3:14b (без цензури)...
call "%~dp0run.bat" --model huihui_ai/qwen3-abliterated:14b --timeout 240
goto menu

:cloud_models
echo.
echo Cloud моделі потребують налаштування MEDFARL_LLM_URL
echo Спробуйте локальні моделі (1-7) або натисніть 11
pause
goto menu

:normal
echo.
echo Запуск з перевіркою Ollama...
call "%~dp0run.bat"
goto menu

:quick
echo.
echo Швидкий запуск...
call "%~dp0run-quick.bat"
goto menu

:unsafe
echo.
echo Запуск у режимі повного доступу...
call "%~dp0run-unsafe.bat"
goto menu

:healthcheck
echo.
echo Перевірка системи...
call "%~dp0run.bat" --healthcheck
goto menu

:listmodels
echo.
echo Список доступних моделей...
call "%~dp0run.bat" --list-models
goto menu

:benchmark
echo.
echo Бенчмарк моделей (qwen3.5:4b, qwen3.5:9b, llama3.2:3b)...
call "%~dp0run.bat" --benchmark-models qwen3.5:4b qwen3.5:9b llama3.2:3b
goto menu

:streaming
echo.
echo Запуск в інтерактивному режимі (Streaming)...
call "%~dp0run-streaming.bat"
goto menu

:end
echo.
echo До побачення!
exit /b 0
