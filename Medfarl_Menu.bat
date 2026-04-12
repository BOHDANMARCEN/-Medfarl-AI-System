@echo off
chcp 65001 >nul
title Medfarl AI System - Меню

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
python main.py --model qwen3.5:4b
pause
goto menu

:model_qwen_9b
echo.
echo Запуск з моделлю qwen3.5:9b...
python main.py --model qwen3.5:9b
pause
goto menu

:model_llama_3b
echo.
echo Запуск з моделлю llama3.2:3b...
python main.py --model llama3.2:3b
pause
goto menu

:model_gemma
echo.
echo Запуск з моделлю gemma-abliterated...
python main.py --model gemma-abliterated
pause
goto menu

:model_gpt_20b
echo.
echo Запуск з моделлю gpt-oss-20b...
python main.py --model gpt-oss-20b --timeout 240
pause
goto menu

:model_qwen25_14b
echo.
echo Запуск з моделлю qwen2.5-1m:14b...
python main.py --model huihui_ai/qwen2.5-1m-abliterated:14b --timeout 240
pause
goto menu

:model_qwen3_14b
echo.
echo Запуск з моделлю qwen3:14b (без цензури)...
python main.py --model huihui_ai/qwen3-abliterated:14b --timeout 240
pause
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
python main.py
pause
goto menu

:quick
echo.
echo Швидкий запуск...
python main.py --skip-healthcheck
pause
goto menu

:unsafe
echo.
echo Запуск у режимі повного доступу...
python main.py --unsafe-full-access --skip-healthcheck
pause
goto menu

:healthcheck
echo.
echo Перевірка системи...
python main.py --healthcheck
pause
goto menu

:listmodels
echo.
echo Список доступних моделей...
python main.py --list-models
pause
goto menu

:benchmark
echo.
echo Бенчмарк моделей (qwen3.5:4b, qwen3.5:9b, llama3.2:3b)...
python main.py --benchmark-models qwen3.5:4b qwen3.5:9b llama3.2:3b
pause
goto menu

:streaming
echo.
echo Запуск в інтерактивному режимі (Streaming)...
python main.py --stream --model qwen3.5:4b
pause
goto menu

:end
echo.
echo До побачення!
exit /b 0
