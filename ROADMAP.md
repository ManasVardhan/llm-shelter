# Roadmap — llm-shelter

## v0.2 (Planned)

### ⏱️ Rate Limiting Validator
Built-in rate limiter that caps requests per user/key/IP to prevent abuse and runaway costs before they hit the LLM API.

### 🔍 Custom Regex Patterns
Allow users to define custom regex-based validators for domain-specific PII or sensitive content detection beyond the built-in rules.

### 📋 OWASP LLM Top 10 Checklist
Automated checks mapped to the OWASP Top 10 for LLM Applications, with pass/fail reporting and remediation guidance.

### 🧩 FastAPI / Flask Middleware
Drop-in middleware for popular Python web frameworks that automatically validates inputs and outputs through llm-shelter's pipeline.

---

Have ideas? Open an issue or start a discussion!
