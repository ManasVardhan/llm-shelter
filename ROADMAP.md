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

### 🧰 Policy Files
Declarative YAML/JSON policy files that define the full pipeline (validators, actions, thresholds, custom regex patterns, optional audit log), loaded with `GuardrailPipeline.from_policy()`, `load_pipeline()`, or `--policy` on the scan command. A `policy` CLI command validates a file and prints the resolved pipeline (text or JSON) with exit code 1 on invalid policies for CI gating. Strict validation rejects unknown types, keys, and actions with precise error locations.

### 🌐 Policy Registry
Policies load from HTTPS URLs with SHA-256 checksum pinning, so fleets of services pull one centrally reviewed guardrail policy at startup. `from_policy()`/`load_pipeline()` accept a URL plus optional `checksum`, the scan command gains `--policy-checksum`, and the `policy` command validates URLs and prints the content digest for pinning. Plain http is restricted to localhost and responses are capped at 1 MB.

### 🧩 Validator Plugins
Entry-point based third-party validators: packages declare validators in the `llm_shelter.validators` entry point group and policies reference them by type name next to the built-ins, with settings passed to the factory as keyword arguments and `default_action` support. `register_validator()` covers in-process registration for application-local checks, plugins can never shadow built-in types, invalid factories are rejected with precise errors, and the `llm-shelter plugins` CLI lists installed plugins (`--json-output`) and exits 1 when any entry point fails to load.

### 🚦 Streaming Guardrails
`StreamGuard` wraps any pipeline for incremental validation of streamed LLM output: feed chunks as they arrive, safe (redacted) text is released as soon as it clears a configurable holdback window that catches findings spanning chunk boundaries, and `StreamBlocked` is raised the moment a validator blocks so the stream can be cut with nothing further released. `wrap()` adapts any chunk iterator, one aggregate audit record is written per stream when an audit logger is attached, and the `llm-shelter stream` CLI pipes stdin through the guardrails incrementally (exit 2 on block) with the same validator, pattern, and policy flags as `scan`.

## v0.5 (Planned)

### 🧵 Async Streaming Adapters
`async` counterparts for streaming: an `awrap()` adapter for async chunk iterators and drop-in wrappers for OpenAI and Anthropic streaming responses, so async web apps guard token streams without threading glue.

---

Have ideas? Open an issue or start a discussion!
