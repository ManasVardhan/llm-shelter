# Roadmap - llm-shelter

## Shipped

### ⏱️ Rate Limiting Validator
`RateLimitValidator` caps requests per user/key/IP with a thread-safe sliding window (`RateLimiter`), including remaining/retry_after/reset inspection and per-caller buckets via `key_func`.

## v0.2 (Planned)

### 🔍 Custom Regex Patterns
Allow users to define custom regex-based validators for domain-specific PII or sensitive content detection beyond the built-in rules.

### 📋 OWASP LLM Top 10 Checklist
Automated checks mapped to the OWASP Top 10 for LLM Applications, with pass/fail reporting and remediation guidance.

### 🧩 FastAPI / Flask Middleware
Drop-in middleware for popular Python web frameworks that automatically validates inputs and outputs through llm-shelter's pipeline.

---

Have ideas? Open an issue or start a discussion!
