# Roadmap - llm-shelter

## Shipped

### 📋 OWASP LLM Top 10 Checklist
`llm-shelter audit` and `audit_pipeline()` map a guardrail pipeline to the OWASP Top 10 for LLM Applications: automated pass/partial/fail checks for prompt injection, insecure output handling, model DoS, and sensitive information disclosure, manual review items with remediation guidance for the rest, JSON output, and a `--fail-on-gaps` CI gate.

### ⏱️ Rate Limiting Validator
`RateLimitValidator` caps requests per user/key/IP with a thread-safe sliding window (`RateLimiter`), including remaining/retry_after/reset inspection and per-caller buckets via `key_func`.

### 🔍 Custom Regex Patterns
`RegexValidator` with named `RegexPattern` rules for domain-specific PII (employee IDs, tickets, codenames), auto-derived redaction placeholders, `from_specs` LABEL=REGEX parsing, and a repeatable `-p` flag on the scan, batch, and report CLI commands.

### 🧩 FastAPI / Flask Middleware
Drop-in middleware for both major Python web stacks: `ShelterMiddleware` (ASGI, FastAPI/Starlette) and `ShelterWSGIMiddleware` (WSGI, Flask/Django/Bottle). Both intercept POST/PUT/PATCH bodies, extract text from common JSON fields, redact in place with corrected Content-Length, return 422 with findings on block, and support path scoping plus a custom `on_block` payload.

### 📊 Audit Log Sink
`GuardrailPipeline(audit=AuditLogger(...))` appends one JSON line per decision: action taken, per-validator findings and latency, input/output sizes, and optional caller context, with the scanned text never logged. Thread-safe file or stream sinks, `iter_records()` / `summarize()` for offline analysis, a `--audit-log` flag on the scan command, and an `audit-log` CLI command with summary, `--tail`, and `--json-output` views.

## v0.2 (Planned)

### 🧰 Policy Files
Define a full guardrail pipeline in a YAML policy file (validators, actions, thresholds, custom patterns), load it with `GuardrailPipeline.from_policy()` or `--policy` on the CLI, and share one reviewed policy across services.

---

Have ideas? Open an issue or start a discussion!
