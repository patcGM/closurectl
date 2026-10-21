# Incident reports

`closurectl report` renders a deterministic, offline HTML view only after it
recomputes the plan, verifies the Ed25519 receipt, and binds a separately
supplied evidence artifact to the observations signed by that receipt.

```bash
closurectl report authority-graph.json closure-plan.json \
  closure-receipt.json evidence.json \
  --public-key incident-signing.pub.pem \
  --preview execution-preview.json \
  --journal execution.jsonl \
  --out closure-report.html
```

The command fails closed when:

- graph, plan, evidence, receipt, or signing key do not bind to one another;
- a journal event has an invalid shape, timestamp, hash chain, transition,
  action, phase, operation, or target, or does not bind to the separately
  validated execution preview;
- the output path resolves to any input path;
- the receipt signature or canonical receipt state is invalid.

The report contains no scripts, links, or external assets. Its Content Security
Policy starts with `default-src 'none'` and permits only the embedded style
block. HTML metacharacters are escaped, and Unicode control and bidirectional
formatting characters are rendered as visible `\uXXXX` text.

The CLI prints `report sha256: <digest>` after the atomic write. Verify it
independently before transfer:

```bash
sha256sum closure-report.html
```

```powershell
(Get-FileHash .\closure-report.html -Algorithm SHA256).Hash.ToLowerInvariant()
```

The HTML is a presentation of scoped signed artifacts, not a new attestation.
Preserve the graph, plan, evidence, receipt, public key, optional journal, and
reported SHA-256 alongside it.
