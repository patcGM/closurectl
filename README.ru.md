# closurectl

[English](README.md) | Русский

**Проверьте, действительно ли отзыв credentials закрыл инцидент.**

`closurectl` — локальный open-source CLI для планирования и проверки
containment после компрометации учётной записи разработчика. Он моделирует
украденные credentials, производные облачные сессии, задания CI в очереди и
права публикации как граф полномочий, после чего вычисляет набор действий,
перекрывающий все объявленные пути к критичным операциям.

> [!IMPORTANT]
> `closurectl` выполняет реальные высокорисковые mutations для точных GitHub
> Actions, npm token и AWS IAM role targets. Обязательны короткоживущий preview,
> подтверждение точного digest, отдельная recovery identity, hash-chained
> journal и независимая проверка. `CLOSED` относится только к объявленному
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

Готовые исполняемые файлы находятся в
[GitHub Releases](https://github.com/patcGM/closurectl/releases). Текущий
release pipeline публикует Windows x86-64, Linux x86-64/arm64 и нативные macOS
arm64/x86-64. Сравните SHA-256 файла со значением из `SHA256SUMS.txt`.

```powershell
# Windows PowerShell
$expected = ((Select-String ' closurectl-windows-x86_64.exe$' .\SHA256SUMS.txt).Line -split '\s+')[0]
$actual = (Get-FileHash .\closurectl-windows-x86_64.exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 mismatch" }
gh attestation verify .\closurectl-windows-x86_64.exe --repo patcGM/closurectl `
  --signer-workflow patcGM/closurectl/.github/workflows/release.yml
.\closurectl-windows-x86_64.exe --version
```

```bash
# Linux: сначала загрузите все release assets
sha256sum -c SHA256SUMS.txt
gh attestation verify closurectl-linux-x86_64 --repo patcGM/closurectl \
  --signer-workflow patcGM/closurectl/.github/workflows/release.yml
chmod +x closurectl-linux-x86_64
./closurectl-linux-x86_64 --version
```

На macOS используйте `shasum -a 256 -c SHA256SUMS.txt`, затем ту же команду
`gh attestation verify` для выбранного binary.

Бинарники пока не подписаны сертификатом разработчика и не notarized. Другой
вариант установки с привязкой к конкретному релизу:

```bash
pipx install "git+https://github.com/patcGM/closurectl.git@v1.0.0"
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

closurectl report authority-graph.json closure-plan.json closure-receipt.json `
  evidence.json `
  --public-key incident-signing.pub.pem `
  --out closure-report.html
```

Команда отдельно сверяет evidence с подписанным receipt и печатает SHA-256
созданного HTML. Подробности: [`docs/INCIDENT_REPORTS.md`](docs/INCIDENT_REPORTS.md).

Приватный ключ нельзя хранить на заражённой машине или добавлять в git.

## Проверка recovery readiness на чистой машине

До инцидента настройте на заведомо чистой машине mutation и
observer/recovery credentials, описанные ниже, и проверьте только нужные
провайдеры:

```powershell
closurectl readiness `
  --provider github `
  --provider npm `
  --provider aws
```

Команда выполняет только read-only запросы. Она проверяет, что GitHub использует
две разные accounts, npm — разные credentials одной account, npm CLI 11.18.0 и
доступный recovery token listing, а AWS — два разных principals одной account.
Значения credentials не выводятся. Ошибка одного провайдера даёт `NOT_READY`,
но остальные проверки продолжаются; exit code равен `5`. Для
machine-readable результата укажите глобальный `--json` перед `readiness`.

Readiness не читает incident target и не доказывает target permissions. Перед
любой mutation команда `execute preview` по-прежнему проверяет точный resource,
его текущее состояние и permissions.

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

## Инвентаризация AWS IAM

Используется отдельный read-only профиль AWS CLI и точные имена ролей.
Environment access keys не передаются дочернему процессу:

```powershell
closurectl inventory aws `
  --profile incident-observer `
  --role ProductionDeployer `
  --out aws-inventory.json
```

Сохраняются только разрешённые поля роли и условия GitHub OIDC trust. Для
service-linked и IAM Identity Center managed roles live execution запрещён.

## Incident wizard: inventory → graph

Inventory не превращается в security claim автоматически. Сначала создаётся
draft с предлагаемыми путями:

```powershell
closurectl incident draft `
  --title "Compromised release identity" `
  --github-inventory github-inventory.json `
  --npm-inventory npm-inventory.json `
  --aws-inventory aws-inventory.json `
  --out incident-draft.json
```

Затем каждый путь подтверждается интерактивно:

```powershell
closurectl incident wizard incident-draft.json --out authority-graph.json
```

Для автоматизации используйте `incident build` с повторяемым `--select` и
точным `--confirm DRAFT_DIGEST`. Если inventory был усечён, draft добавляет
обязательный незакрываемый путь, и план становится `BLOCKED`.

## Контролируемый live containment

Запускайте мутации только с чистой машины и заранее проверенной recovery
identity. Исполнимы только четыре точных контракта:

- `github:disable_workflow` и target
  `github://OWNER/REPO/actions/workflows/NUMERIC_ID`;
- `github:cancel_run` и target
  `github://OWNER/REPO/actions/runs/NUMERIC_ID`;
- `npm:revoke_token` и target
  `npm://registry.npmjs.org/tokens/FULL_TOKEN_ID`.
- `aws:revoke_role_sessions` и target
  `aws://ACCOUNT_ID/iam/roles/ROLE_NAME`.

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

Для AWS нужны два разных CLI profiles двух разных principals в одном account:

```powershell
$env:CLOSURECTL_AWS_MUTATION_PROFILE = "incident-mutation"
$env:CLOSURECTL_AWS_OBSERVER_PROFILE = "incident-observer"
```

AWS executor создаёт уникальную inline policy
`ClosureCtlRevokeOlderSessions-*`. Её имя, cutoff, digest документа, target и
неизменяемый IAM `RoleId` фиксируются подтверждённым preview; общая policy
`AWSRevokeOlderSessions` никогда не перезаписывается. Действие отсекает все
sessions роли, выпущенные до cutoff, а не одну session атакующего. До окончания
пятиминутного IAM propagation window evidence остаётся `INDETERMINATE` и
должно видеть именно эту policy.

OTP нельзя передавать аргументом CLI. Если npm требует OTP, используйте
защищённую переменную/config npm и удалите её сразу после операции.

Сначала создайте и вручную проверьте preview:

```powershell
closurectl execute preview authority-graph.json closure-plan.json `
  --out execution-preview.json
```

После проверки immutable targets и identities подтвердите точный
`preview_digest`:

```powershell
closurectl execute apply authority-graph.json closure-plan.json `
  execution-preview.json --confirm PREVIEW_DIGEST `
  --journal execution.jsonl
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
readiness/execution/evidence, `130` — прерывание. Глобальный `--json` перед
командой выводит machine-readable summary.

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
[правила работы с receipt keys](docs/RECEIPT_KEYS.md) и
[AWS role-session containment](docs/AWS_ROLE_SESSIONS.md). Точные permissions и
версии provider CLI описаны в
[`docs/PROVIDER_REQUIREMENTS.md`](docs/PROVIDER_REQUIREMENTS.md), стабильные
гарантии — в [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

## Разработка

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m unittest discover -s tests -v
```

Правила участия находятся в [CONTRIBUTING.md](CONTRIBUTING.md), поддержка — в
[SUPPORT.md](SUPPORT.md), политика безопасности — в
[SECURITY.md](SECURITY.md).

Лицензия: MIT.
