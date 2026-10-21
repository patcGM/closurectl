# closurectl

[English](README.md) | Русский

**Проверьте, действительно ли отзыв credentials закрыл инцидент.**

`closurectl` — локальный open-source CLI для планирования и проверки
containment после компрометации учётной записи разработчика. Он моделирует
украденные credentials, производные облачные сессии, задания CI в очереди и
права публикации как граф полномочий, после чего вычисляет набор действий,
перекрывающий все объявленные пути к критичным операциям.

> [!IMPORTANT]
> Версия 0.1 — alpha. Она планирует и проверяет containment, но не отзывает
> реальные доступы автоматически. Интеграции GitHub и npm работают только на
> чтение. Статус `CLOSED` относится исключительно к объявленному графу и не
> доказывает полное удаление атакующего.

## Зачем это нужно

Ответ API `204 Revoked` означает, что один запрос принят. Он не доказывает, что:

- ранее выпущенная AWS-сессия перестала работать;
- поставленный в очередь deployment не выполнится;
- удалены другие OAuth grants и deploy keys;
- скомпрометированный workflow больше не выпустит новый доступ;
- в модель внесены все пути атакующего.

`closurectl` отделяет **запрос на отзыв** от **проверки результата**.

## Быстрый запуск

Потребуется Python 3.11 или новее:

```powershell
git clone https://github.com/patcGM/closurectl.git
cd closurectl
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
closurectl demo --dir closurectl-demo
```

Демонстрация полностью локальная. Она создаст граф инцидента, closure-план,
одноразовую пару Ed25519-ключей, evidence и подписанный receipt.

Ожидаемый результат:

```text
status: PLANNED
actions: 5
  1. [stop_minting] github:disable_workflow -> release.yml
  2. [cancel_pending] github:cancel_workflow_run -> queued-production-deploy
  3. [revoke_descendants] aws:invalidate_role_sessions -> production-deployer
  4. [revoke_roots] npm:revoke_publication_credential -> affected-maintainer
  5. [revoke_roots] github:revoke_session -> maintainer-session
receipt: CLOSED
```

## Установка

Готовые исполняемые файлы для Windows x86-64, Linux x86-64 и macOS находятся
в [GitHub Releases](https://github.com/patcGM/closurectl/releases). Сравните
SHA-256 файла со значением из `SHA256SUMS.txt`.

```powershell
# Windows PowerShell
Get-FileHash .\closurectl-windows-x86_64.exe -Algorithm SHA256
.\closurectl-windows-x86_64.exe --version
```

```bash
# Linux
sha256sum closurectl-linux-x86_64
chmod +x closurectl-linux-x86_64
./closurectl-linux-x86_64 --version

# macOS
shasum -a 256 closurectl-macos
chmod +x closurectl-macos
./closurectl-macos --version
```

Бинарники пока не подписаны сертификатом разработчика и не notarized. Другой
вариант установки с привязкой к конкретному релизу:

```bash
pipx install "git+https://github.com/patcGM/closurectl.git@v0.1.0"
```

## Основной процесс

Проверить граф:

```bash
closurectl validate authority-graph.json
```

Построить минимальный closure cut:

```bash
closurectl plan authority-graph.json --out closure-plan.json
```

Команда `plan` выводит строку `plan:`. Это значение необходимо записать в поле
`plan_digest` файла `evidence.json`. Для каждого action указывается
`VERIFIED_CLOSED`, `STILL_OPEN` или `INDETERMINATE`.

Создать отдельную пару ключей на чистом компьютере в PowerShell:

```powershell
closurectl keygen `
  --private-key incident-signing.pem `
  --public-key incident-signing.pub.pem
```

Подписать результаты независимых проверок:

```powershell
closurectl receipt authority-graph.json closure-plan.json evidence.json `
  --private-key incident-signing.pem `
  --out closure-receipt.json
```

Проверить подпись:

```powershell
closurectl verify closure-receipt.json `
  --public-key incident-signing.pub.pem `
  --graph authority-graph.json `
  --plan closure-plan.json
```

Приватный ключ нельзя хранить на заражённой машине или добавлять в git.

## Инвентаризация GitHub

Токен передаётся только через переменную окружения и не сохраняется:

```powershell
$env:GITHUB_TOKEN = gh auth token
closurectl inventory github `
  --repo OWNER/REPOSITORY `
  --out github-inventory.json
Remove-Item Env:GITHUB_TOKEN
```

Собираются только разрешённые поля: permissions репозитория, workflows,
queued runs, deploy keys и OAuth scopes. Результаты ограничены 100 объектами на
endpoint; пустой список не считается доказательством отсутствия доступа.

## Инвентаризация npm

Используется уже авторизованный npm CLI. Значения и частичные ключи credentials
отбрасываются:

```powershell
closurectl inventory npm `
  --package package-name `
  --out npm-inventory.json
```

## Статусы

- `CLOSED` — каждое действие независимо подтверждено как закрытое.
- `PARTIAL` — закрыта только часть действий.
- `OPEN` — хотя бы один путь подтверждённо остаётся открытым.
- `INDETERMINATE` — для вывода недостаточно данных.
- `BLOCKED` — в графе есть путь, который невозможно перекрыть объявленными
  средствами.

## Ограничения

Инструмент не ищет malware, не обнаруживает неизвестные украденные credentials,
не восстанавливает forensic image, не отменяет уже выполненные операции и не
заменяет процедуры провайдера или профессиональную incident-response команду.

Перед реальным применением прочитайте
[модель угроз](docs/THREAT_MODEL.md) и
[формат графа](docs/GRAPH_FORMAT.md).

## Разработка

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m unittest discover -s tests -v
```

Правила участия находятся в [CONTRIBUTING.md](CONTRIBUTING.md), политика
безопасности — в [SECURITY.md](SECURITY.md).

Лицензия: MIT.
