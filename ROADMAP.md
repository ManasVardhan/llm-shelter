# Roadmap - llm-shelter

## Shipped

### 📋 OWASP LLM Top 10 Checklist
`llm-shelter audit` and `audit_pipeline()` map a guardrail pipeline to the OWASP Top 10 for LLM Applications: automated pass/partial/fail checks for prompt injection, insecure output handling, model DoS, and sensitive information disclosure, manual review items with remediation guidance for the rest, JSON output, and a `--fail-on-gaps` CI gate.

### ⏱️ Rate Limiting Validator
`RateLimitValidator` caps requests per user/key/IP with a thread-safe sliding window (`RateLimiter`), including remaining/retry_after/reset inspection and per-caller buckets via `key_func`.

### 🔍 Custom Regex Patterns
`RegexValidator` with named `RegexPattern` rules for domain-specific PII (employee IDs, tickets, codenames), auto-derived redaction placeholders, `from_specs` LABEL=REGEX parsing, and a repeatable `-p` flag on the scan, batch, and report CLI commands.

## v0.2 (Planned)

### 🧩 FastAPI / Flask Middleware
Drop-in middleware for popular Python web frameworks that automatically validates inputs and outputs through llm-shelter's pipeline.

---

Have ideas? Open an issue or start a discussion!
