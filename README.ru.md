# closurectl

[English](README.md) | Русский

**Проверьте, действительно ли отзыв credentials закрыл инцидент.**

`closurectl` — локальный open-source CLI для планирования и проверки
containment после компрометации учётной записи разработчика. Он моделирует
украденные credentials, производные облачные сессии, задания CI в очереди и
права публикации как граф полномочий, после чего вычисляет набор действий,
перекрывающий все объявленные пути к критичным операциям.

> [!IMPORTANT]
> Версия 0.2.0a1 — alpha. Она добавляет opt-in экспериментальные мутации для
> конкретных GitHub Actions workflows/runs и конкретных npm token IDs.
> Обязательны короткоживущий preview, подтверждение digest, отдельная recovery
> identity и независимая проверка. `CLOSED` относится только к объявленному
> графу и не доказывает полное удаление атакующего.

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

Готовые исполняемые файлы для Windows x86-64 и Linux x86-64 находятся в
[GitHub Releases](https://github.com/patcGM/closurectl/releases). Сравните
SHA-256 файла со значением из `SHA256SUMS.txt`. На macOS пока используйте
`pipx` или установку из исходников.

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
```

Бинарники пока не подписаны сертификатом разработчика и не notarized. Другой
вариант установки с привязкой к конкретному релизу:

```bash
pipx install "git+https://github.com/patcGM/closurectl.git@v0.2.0a1"
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

Собираются только разрешённые поля: permissions репозитория, workflows, все
активные runs, deploy keys и OAuth scopes. Коллекции ограничены 500 объектами
с явным флагом truncation; пустой список не доказывает отсутствие доступа.

## Инвентаризация npm

Используется уже авторизованный npm CLI. Значения и частичные ключи credentials
отбрасываются:

```powershell
closurectl inventory npm `
  --package package-name `
  --out npm-inventory.json
```

Один запуск принимает не более 50 packages и 1 000 элементов в коллекции.

## Экспериментальный live revocation

Запускайте мутации только с чистой машины и заранее проверенной recovery
identity. Исполнимы только три точных контракта:

- `github:disable_workflow` и target
  `github://OWNER/REPO/actions/workflows/NUMERIC_ID`;
- `github:cancel_run` и target
  `github://OWNER/REPO/actions/runs/NUMERIC_ID`;
- `npm:revoke_token` и target
  `npm://registry.npmjs.org/tokens/FULL_TOKEN_ID`.

Для GitHub нужны токены двух разных accounts:

```powershell
$env:GITHUB_TOKEN = "mutation-identity-token"
$env:CLOSURECTL_GITHUB_OBSERVER_TOKEN = "independent-observer-token"
```

Для npm нужны два разных userconfig-файла одной npm account. Recovery config
должен сохранять доступ после отзыва целевого token:

```powershell
$env:CLOSURECTL_NPM_MUTATION_USERCONFIG = "$HOME\.npmrc-mutation"
$env:CLOSURECTL_NPM_RECOVERY_USERCONFIG = "$HOME\.npmrc-recovery"
```

OTP нельзя передавать аргументом CLI. Если npm требует OTP, используйте
защищённую переменную/config npm и удалите её сразу после операции.

Сначала создайте и вручную проверьте preview:

```powershell
closurectl execute preview authority-graph.json closure-plan.json `
  --out execution-preview.json --experimental
```

После проверки immutable targets и identities подтвердите точный
`preview_digest`:

```powershell
closurectl execute apply authority-graph.json closure-plan.json `
  execution-preview.json --confirm PREVIEW_DIGEST `
  --journal execution.jsonl --experimental
```

После сбоя используйте `execute resume` с теми же файлами. Resume только
сверяет уже записанные как requested действия, не повторяет мутацию вслепую и
не начинает новые действия по просроченному preview. После reconciliation для
оставшихся действий создайте новый preview и новый journal. Независимое
evidence:

```powershell
closurectl observe authority-graph.json closure-plan.json `
  execution-preview.json --journal execution.jsonl --out evidence.json
```

Для npm `VERIFIED_CLOSED` возможен только после того, как token отсутствует по
истечении часового окна propagation. Ответ mutation API сам по себе не является
evidence закрытия.

Exit codes: `0` — закрыто/успешно, `2` — ошибка входных данных или провайдера,
`3` — `BLOCKED`, `4` — корректный, но не закрытый receipt, `5` — незавершённые
execution/evidence, `130` — прерывание. Глобальный `--json` перед командой
выводит machine-readable summary.

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
[формат графа](docs/GRAPH_FORMAT.md), а также
[правила работы с receipt keys](docs/RECEIPT_KEYS.md).

## Разработка

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m unittest discover -s tests -v
```

Правила участия находятся в [CONTRIBUTING.md](CONTRIBUTING.md), политика
безопасности — в [SECURITY.md](SECURITY.md).

Лицензия: MIT.
