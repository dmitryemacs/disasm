# disasm-mcp — MCP-сервер к отладчику disasm

Этот каталог содержит MCP-фронтенд к Emacs-пакету `disasm`. Он позволяет
агенту (например, OpenCode) управлять отладчиком: смотреть состояние,
дизассемблировать, читать и писать память, ставить точки останова,
запускать/подключать цели и исполнять их.

## Как это устроено

```
агент  ──stdio JSON-RPC──▶  disasm-mcp-server.mjs  ──TCP JSON-строки──▶  Emacs (disasm-mcp.el)
```

- `disasm-mcp-server.mjs` — MCP-сервер без сторонних зависимостей (Node
  ≥ 18). Говорит по stdio с хост-агентом и по TCP с Emacs.
- `disasm-mcp.el` — TCP-слушатель внутри Emacs. Переводит запросы в
  обычные команды пакета, поэтому всё, что делает агент, отражается в
  панелях, листинге и hex-виде; ход работы виден в буфере
  `*disasm-agent*` (`C-c d L`).

Слушатель принимает соединения только с петлевого интерфейса и требует
токен, так что держать его включённым безопасно.

## Запуск

Сначала — Emacs с загруженным `disasm` (слушатель поднимается сам):

```elisp
(require 'disasm)          ; поднимет слушатель на 127.0.0.1:37373
```

Затем подключите сервер к агенту:

```sh
opencode mcp add disasm --global -- \
  node "$HOME/.emacs.d/lisp/disasm/mcp/disasm-mcp-server.mjs"
opencode mcp list          # ожидаем: ✓ disasm connected
```

### Переменные окружения

| Переменная              | По умолчанию                  | Смысл                          |
| ----------------------- | ----------------------------- | ------------------------------ |
| `DISASM_MCP_HOST`       | `127.0.0.1`                   | адрес слушателя Emacs          |
| `DISASM_MCP_PORT`       | `37373`                       | порт слушателя Emacs           |
| `DISASM_MCP_TOKEN_FILE` | `~/.emacs.d/disasm-mcp-token` | файл с токеном доступа         |
| `DISASM_MCP_TIMEOUT`    | `15000`                       | таймаут одного запроса, мс     |
| `DISASM_MCP_WAIT`       | `30000`                       | таймаут ожидания остановки, мс |

## Инструменты

Один инструмент MCP — одна (или несколько) операций слушателя:

| Инструмент      | Операция(и)                         |
| --------------- | ----------------------------------- |
| `sessions`      | `sessions`                          |
| `state`         | `state` (+ `include`: registers, flags, threads, frames, modules, breakpoints) |
| `disassemble`   | `disassemble`                       |
| `read_memory`   | `read_memory`                       |
| `write_memory`  | `write_memory`                      |
| `set_register`  | `set_register`                      |
| `goto`          | `goto`                              |
| `select_thread` | `select_thread`                     |
| `select_frame`  | `select_frame`                      |
| `breakpoint`    | `breakpoint` (set / delete / list / clear) |
| `step`          | `step` (stepi / nexti / finish)     |
| `continue`      | `continue`                          |
| `interrupt`     | `interrupt`                         |
| `attach`        | `attach`                            |
| `launch`        | `launch`                            |
| `detach`        | `detach`                            |
| `open_file`     | `open_file`                         |
| `wait`          | `state` в цикле до остановки цели   |

Инструменты, возобновляющие цель (`continue`, `step`, `launch`), по
умолчанию ждут её остановки (`wait: true`) и возвращают снимок состояния
в поле `state_snapshot`.

## Проверка

```sh
node --test mcp/test/bridge.test.mjs
```

Тесты не требуют ни Emacs, ни сети: TCP-сторона заменяется заглушкой.
Полный набор тестов пакета — `test/disasm-tests.el` (см. основной README).

## Диагностика

- **`Cannot reach the disasm debugger in Emacs on 127.0.0.1:37373…`** —
  Emacs с загруженным `disasm` не слушает (или слушает другой порт), либо
  файл с токеном ещё не создан. Проверьте `disasm-mcp-port` и
  `DISASM_MCP_PORT`, запустите `M-x disasm-mcp-start` и загляните в
  `*Messages*`.
