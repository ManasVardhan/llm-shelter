# Roadmap - llm-shelter

## Shipped

### ⏱️ Rate Limiting Validator
`RateLimitValidator` caps requests per user/key/IP with a thread-safe sliding window (`RateLimiter`), including remaining/retry_after/reset inspection and per-caller buckets via `key_func`.

### 🔍 Custom Regex Patterns
`RegexValidator` with named `RegexPattern` rules for domain-specific PII (employee IDs, tickets, codenames), auto-derived redaction placeholders, `from_specs` LABEL=REGEX parsing, and a repeatable `-p` flag on the scan, batch, and report CLI commands.

## v0.2 (Planned)

### 📋 OWASP LLM Top 10 Checklist
Automated checks mapped to the OWASP Top 10 for LLM Applications, with pass/fail reporting and remediation guidance.

### 🧩 FastAPI / Flask Middleware
Drop-in middleware for popular Python web frameworks that automatically validates inputs and outputs through llm-shelter's pipeline.

---

Have ideas? Open an issue or start a discussion!
