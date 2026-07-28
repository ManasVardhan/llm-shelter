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

## v0.2 (Planned)

### 📊 Audit Log Sink
Structured JSONL logging of every pipeline decision (validator, action, findings, latency) for compliance trails and offline analysis.

---

Have ideas? Open an issue or start a discussion!
