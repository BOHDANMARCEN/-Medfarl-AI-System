"""Small local project starters; creating one never installs or runs software."""
from __future__ import annotations

PRIVATE_STATE_IGNORE = '.medfarl/sessions/\n.medfarl/checkpoints/\n'

def project_files(template: str, name: str) -> dict[str, str]:
    if template == 'empty':
        return {'README.md': f'# {name}\n\nНовий проєкт.\n', '.gitignore': '.env\n.venv/\n__pycache__/\n' + PRIVATE_STATE_IGNORE}
    if template == 'python':
        return {
            'README.md': f'# {name}\n\nPython 3.10+. Додаткові залежності не потрібні.\n\n'
                         'Запуск: `python main.py --name Світ`\n\n'
                         'Перевірка: `python -m unittest discover -s tests`\n',
            '.gitignore': '__pycache__/\n*.py[cod]\n.venv/\n.env\n' + PRIVATE_STATE_IGNORE,
            'main.py': 'import argparse\n\n\ndef greet(name: str) -> str:\n'
                       '    return f"Привіт, {name}!"\n\n\ndef main() -> None:\n'
                       '    parser = argparse.ArgumentParser()\n'
                       '    parser.add_argument("--name", default="Світ")\n'
                       '    args = parser.parse_args()\n    print(greet(args.name))\n\n\n'
                       'if __name__ == "__main__":\n    main()\n',
            'tests/test_main.py': 'import unittest\nfrom main import greet\n\n\n'
                                  'class GreetingTests(unittest.TestCase):\n'
                                  '    def test_greet(self):\n'
                                  '        self.assertEqual(greet("Світ"), "Привіт, Світ!")\n\n\n'
                                  'if __name__ == "__main__":\n    unittest.main()\n',
        }
    if template == 'web':
        return {
            'README.md': f'# {name}\n\nВідкрийте `index.html` у браузері або запустіть\n'
                         '`python -m http.server 8000 --bind 127.0.0.1`\n'
                         'і відкрийте http://127.0.0.1:8000.\n',
            '.gitignore': '.env\nnode_modules/\n' + PRIVATE_STATE_IGNORE,
            'index.html': '<!doctype html>\n<html lang="uk">\n<head>\n'
                          '  <meta charset="utf-8">\n'
                          '  <meta name="viewport" content="width=device-width,initial-scale=1">\n'
                          '  <title>Новий проєкт</title>\n'
                          '  <link rel="stylesheet" href="styles.css">\n'
                          '  <script src="app.js" defer></script>\n</head>\n<body>\n'
                          '  <main><h1>Новий проєкт</h1><p id="message">Готовий до роботи.</p>\n'
                          '  <button id="hello" type="button">Привіт!</button></main>\n'
                          '</body>\n</html>\n',
            'styles.css': ':root { font-family: system-ui, sans-serif; color-scheme: light dark; }\n'
                          'body { margin: 0; min-height: 100vh; display: grid; place-items: center; }\n'
                          'main { max-width: 48rem; padding: 2rem; }\n'
                          'button { padding: .75rem 1.25rem; cursor: pointer; }\n',
            'app.js': 'document.querySelector("#hello").addEventListener("click", () => {\n'
                      '  document.querySelector("#message").textContent = "Привіт, світе!";\n});\n',
        }
    raise ValueError('Невідомий шаблон. Доступні: empty, python, web.')


def file_list(files: dict[str, str]) -> list[dict[str, str]]:
    return [{'path': path, 'content': content} for path, content in files.items()]
