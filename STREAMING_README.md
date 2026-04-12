# 🚀 Інтерактивний Streaming Режим

## Що таке Streaming?

Streaming режим дозволяє бачити відповідь від AI **в реальному часі**, прямо як у:
- Gemini CLI
- ChatGPT
- Claude

Замість того щоб чекати повну відповідь, текст з'являється **поступово**, токен за токеном.

## Як це працює

### Звичайний режим (без streaming):
```
medfarl> що жере RAM
[чекаємо 10-30 секунд...]
[повна відповідь з'являється одразу]
```

### Streaming режим:
```
medfarl> що жере RAM
Зараз найбільше RAM споживають: ← текст з'являється одразу!
- browser.exe: 2048 MB
- editor.exe: 512 MB
[текст друкується в реальному часі] ✓
```

## Переваги

✅ **Миттєвий зворотній зв'язок** - бачиш відповідь одразу  
✅ **Кращий UX** - як спілкування з людиною  
✅ **Не треба чекати** - особливо для довгих відповідей  
✅ **Можна читати поки генерується** - економія часу  

## Як використовувати

### Варіант 1: Бат-файл (найпростіше)
```bat
run-streaming.bat
```

### Варіант 2: Меню
```bat
Medfarl_Menu.bat
# Обери опцію 16
```

### Варіант 3: Командний рядок
```bash
python main.py --stream
python main.py --stream --model qwen3.5:9b
python main.py --stream --model qwen3.5:4b
```

## Що відбувається під час Streaming

1. **LLM генерує токени** → кожен токен одразу відправляється
2. **Клієнт отримує потік** → друк кожного токена в консоль
3. **Tool calls** → коли потрібно використати інструмент:
   - Показується індикатор `🔧 Using tool: ...`
   - Виконується інструмент
   - Продовжується streaming відповіді

## Приклади використання

### Діагностика системи
```
medfarl> діагностика ПК
Запускаю базову діагностику... ← з'являється одразу

CPU: Test CPU (8 cores) ← друк в реальному часі
RAM: 8.5/16.0 GB (53.1%)
Disk C:: 240/512 GB (46.9%)
...
```

### Запитання
```
medfarl> чому комп гальмує
Дивлюсь на процеси... ← миттєво

Ось що знайшов:
- browser.exe використовує 18.5% CPU
- RAM завантажена на 53%
...
```

### Будь-яка мова
```
medfarl> почему компьютер тормозит
Смотрю на процессы... ← русский тоже работает

medfarl> why is my PC slow
Looking at processes... ← English too
```

## Коли використовувати

### ✅ Streaming ідеальний для:
- Довгих діагностичних звітів
- Складних пояснень
- Інтерактивного спілкування
- Навчання та тестування

### ⚠️ Звичайний режим краще для:
- Бенчмарків (потрібен повний контроль)
- Автоматизації (скрипти)
- Коли потрібен точний таймінг

## Технічні деталі

### Як працює під капотом:

1. **HTTP Streaming** → `httpx.stream()` замість `httpx.post()`
2. **Server-Sent Events** → читаємо `data:` лінії
3. **Incremental print** → `print(token, end="", flush=True)`
4. **Tool call detection** → аналізуємо JSON chunks

### Файли змінені:

```
core/llm_client.py
  + chat(stream=True)
  + _stream_response()

core/agent.py
  + _run_agent_loop(stream=True)
  + handle_user_message(stream=True)

main.py
  + --stream argument
  + REPL loop streaming support
```

## Порівняння з іншими інструментами

| Feature | Medfarl Streaming | Gemini CLI | ChatGPT |
|---------|-------------------|------------|---------|
| Real-time tokens | ✅ | ✅ | ✅ |
| Tool use indicators | ✅ 🔧 | ✅ | ✅ |
| Local LLM | ✅ | ❌ | ❌ |
| Privacy | ✅ 100% local | ❌ Cloud | ❌ Cloud |
| Offline capable | ✅ (with Ollama) | ❌ | ❌ |

## Вирішення проблем

### Streaming не працює?
```bash
# Перевірь що Ollama підтримує streaming
python main.py --healthcheck

# Спробуй іншу модель
python main.py --stream --model qwen3.5:4b
```

### Текст з'являється повільно?
```bash
# Збільш timeout для повільних моделей
python main.py --stream --timeout 240
```

### Бажаю кращу якість?
```bash
# Використай більшу модель
python main.py --stream --model qwen3.5:9b
```

## Наступні покращення (TODO)

- [ ] Progress bar для tool execution
- [ ] Syntax highlighting для коду
- [ ] Markdown rendering в консолі
- [ ] Typing animation option
- [ ] Response time statistics

---

**Насолоджуйся інтерактивним спілкуванням з Medfarl AI!** 🎉
