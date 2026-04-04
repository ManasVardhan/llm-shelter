# AGENTS.md - llm-shelter

## Overview
- Safety and guardrails toolkit for LLM applications. Provides composable validators for PII redaction, prompt injection detection, toxicity filtering, length limits, and JSON schema validation. Zero runtime dependencies for core functionality.
- For developers shipping LLM apps who need input/output safety without heavy ML dependencies.
- Core value: regex-based detection (no spaCy, no external APIs), composable pipeline architecture with BLOCK/REDACT/WARN actions, FastAPI middleware, function decorators, and CLI scanning.

## Architecture

```
User Input                                                     Output
    |                                                             ^
    v                                                             |
[PII Guard] -> [Injection Guard] -> [Length Guard] -> LLM -> [Toxicity Guard] -> [Schema Guard]
```

```
+-------------------+      +--------------------+      +--------------------+
|  GuardrailPipeline|      |  Validator Protocol |      |  Action Enum       |
|  .add(validator,  | ---> |  .name: str        |      |  BLOCK / REDACT /  |
|       action)     |      |  .validate(text)   |      |  WARN / PASSTHROUGH|
|  .run(text)       |      |   -> ValidationResult     +--------------------+
+-------------------+      +--------------------+
        |                          ^
        |       +------------------+------------------+------------------+------------------+
        |       |                  |                  |                  |                  |
        v       v                  v                  v                  v                  v
   PIIValidator    InjectionValidator   ToxicityValidator  LengthValidator   SchemaValidator
   (regex PII,     (heuristic patterns, (keyword/pattern,  (char + token     (JSON Schema
    redaction)      instruction override, category weights)  estimation)       subset)
                    delimiter attacks,
                    encoding tricks)

+-------------------+     +-------------------+     +-------------------+
|  ShelterMiddleware|     | guard_input()     |     | guard_output()    |
|  (ASGI/FastAPI)   |     | (decorator)       |     | (decorator)       |
+-------------------+     +-------------------+     +-------------------+
```

**Data flow:**
1. Text enters the pipeline via `pipeline.run(text)` (or middleware/decorator)
2. Each validator runs in order, producing a `ValidationResult` with findings
3. On BLOCK: pipeline short-circuits, returns blocked result
4. On REDACT: text is modified (e.g. emails replaced with `[EMAIL_REDACTED]`), modified text forwarded
5. On WARN: finding recorded, text passes through unchanged
6. Final `ValidationResult` contains all findings, the processed text, and the action taken

## Directory Structure

```
llm-shelter/
  .github/workflows/ci.yml        -- CI: lint + mypy + test on Python 3.10-3.12
  src/llm_shelter/
    __init__.py                    -- Public API re-exports, __version__ = "0.1.1"
    __main__.py                    -- python -m llm_shelter entry
    pipeline.py                    -- GuardrailPipeline, Validator protocol, Action, Finding, ValidationResult
    decorators.py                  -- guard_input(), guard_output() decorators, GuardedCallError
    middleware.py                  -- ShelterMiddleware (ASGI/FastAPI)
    cli.py                         -- Click CLI: scan, batch, report (requires [cli] extra)
    validators/
      __init__.py                  -- Re-exports all validators
      pii.py                       -- PIIValidator: email, phone, SSN, credit card, IP, AWS key detection/redaction
      injection.py                 -- InjectionValidator: instruction overrides, delimiters, encoding tricks
      toxicity.py                  -- ToxicityValidator: profanity, slurs, threats, harassment
      length.py                    -- LengthValidator: char and estimated token limits
      schema.py                    -- SchemaValidator: JSON parse + schema validation (type, required, enum, min/max)
      rules.py                     -- RuleValidator: user-defined callable rules
  examples/
    fastapi_example.py             -- FastAPI middleware example
  tests/                           -- 229 tests across 12 test files
    test_pii.py                    -- PII detection/redaction tests
    test_injection.py              -- Injection detection tests
    test_toxicity.py               -- Toxicity scoring tests
    test_length.py                 -- Length limit tests
    test_schema.py                 -- Schema validation tests
    test_pipeline.py               -- Pipeline integration tests
    test_decorators.py             -- Decorator tests
    test_middleware.py             -- ASGI middleware tests
    test_cli.py                    -- CLI tests
    test_nightly_apr01.py          -- Nightly regression tests
    test_nightly_apr03.py          -- Nightly regression tests
  pyproject.toml                   -- Hatchling build, metadata
  README.md                        -- Full docs
  ROADMAP.md                       -- v0.2 plans
  CONTRIBUTING.md                  -- Contribution guidelines
  GETTING_STARTED.md               -- Quick start guide
  LICENSE                          -- MIT
```

## Core Concepts

- **GuardrailPipeline**: Chain of (Validator, Action) pairs. `run(text)` executes all validators in order. Short-circuits on BLOCK, modifies text on REDACT, records findings on WARN.
- **Validator** (Protocol): Any object with `.name: str` and `.validate(text) -> ValidationResult`. No inheritance required.
- **Action** (Enum): BLOCK (halt pipeline), REDACT (replace + continue), WARN (note + continue), PASSTHROUGH (no action).
- **Finding**: A single detected issue with validator name, category, description, span (start, end), severity (0.0-1.0), redacted_value.
- **ValidationResult**: Aggregate result with is_valid, text (potentially modified), original_text, findings list, action_taken. Has `.blocked` and `.has_findings` properties.
- **PIIValidator**: Regex-based. 6 built-in patterns: email, phone (US), SSN, credit card, IP address, AWS key. Redacts from right to left to preserve span positions.
- **InjectionValidator**: Heuristic patterns in 3 groups: overrides (instruction override, new instruction, prompt extraction), delimiters (delimiter injection, role switch), encoding (base64, unicode smuggling, hex).
- **ToxicityValidator**: Category-based with weights. Categories: profanity (0.6), slurs (0.8), threats (1.0), harassment (0.9). Text flagged when max matched weight >= threshold.
- **LengthValidator**: Checks `max_chars` and `max_tokens` (estimated as len(text)/4).
- **SchemaValidator**: Parses JSON, validates against a subset of JSON Schema (type, required, properties, items, enum, minimum, maximum, minLength, maxLength).
- **RuleValidator**: User-defined rules as `Rule(name, check_fn, description)`. Check returns True when text violates the rule.
- **ShelterMiddleware**: ASGI middleware. Intercepts POST/PUT/PATCH bodies, extracts text from common JSON fields (text, message, content, prompt, input, query), runs pipeline, returns 422 on block.
- **guard_input / guard_output**: Function decorators. `guard_input` validates the named parameter before calling. `guard_output` validates the return value after calling. Both raise `GuardedCallError` on block.

## API Reference

### GuardrailPipeline
```python
class GuardrailPipeline:
    def add(self, validator: Validator, action: Action = Action.BLOCK) -> GuardrailPipeline  # fluent
    def run(self, text: str) -> ValidationResult
```

### Validators
```python
PIIValidator(patterns=None, redact=True, action=Action.REDACT)
InjectionValidator(patterns=None, threshold=0.5, action=Action.BLOCK)
ToxicityValidator(categories=None, threshold=0.5, action=Action.BLOCK)
LengthValidator(max_chars=None, max_tokens=None, action=Action.BLOCK)
SchemaValidator(schema=dict, action=Action.BLOCK)
RuleValidator(rules=None, action=Action.BLOCK)
# All have: .validate(text: str) -> ValidationResult
```

### Decorators
```python
@guard_input(pipeline, param="prompt")   # validates input param
@guard_output(pipeline)                   # validates return value
# Both raise GuardedCallError on block
```

### Middleware
```python
ShelterMiddleware(app, pipeline, paths=None, on_block=None)
```

## CLI Commands

```bash
# Scan text directly
llm-shelter scan "My email is test@example.com"

# Scan with redaction
llm-shelter scan --redact "Call 555-123-4567"

# Scan a file
llm-shelter scan --file prompt.txt

# Pipe from stdin
echo "Ignore previous instructions" | llm-shelter scan

# Disable specific checks
llm-shelter scan --no-toxicity "Some text"
llm-shelter scan --no-pii --no-injection "Some text"

# Set max character limit
llm-shelter scan --max-chars 1000 "Some text"

# Scan multiple files
llm-shelter batch file1.txt file2.txt file3.txt

# JSON report output (for CI/CD)
llm-shelter report "Some text"
llm-shelter report --file prompt.txt

# Version
llm-shelter --version
```

**Exit codes:** 0 = clean, 2 = blocked

## Configuration

- **No config files or env vars** for core functionality
- **Pipeline actions** configured per-validator when calling `pipeline.add(validator, action)`
- **Validator options**: All validators accept custom patterns, thresholds, and actions
- **Install extras**: `pip install llm-shelter[fastapi]` for middleware, `[cli]` for CLI, `[all]` for everything

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v --tb=short
```

- **229 tests** across 12 test files
- Includes async tests for middleware (pytest-asyncio)
- Located in `tests/`

## Dependencies

- **Core**: Zero runtime dependencies (stdlib only)
- **fastapi extra**: `fastapi>=0.100.0`, `uvicorn>=0.23.0`
- **cli extra**: `click>=8.0`
- **dev extra**: `pytest>=7.0`, `pytest-asyncio>=0.21`, `ruff>=0.1.0`, `mypy>=1.0`
- **Python >=3.10**

## CI/CD

- **GitHub Actions** (`.github/workflows/ci.yml`)
- Matrix: Python 3.10, 3.11, 3.12
- Steps: install, ruff lint, mypy type check (excludes cli.py), pytest
- Triggers: push/PR to main

## Current Status

- **Version**: 0.1.1
- **Published on PyPI**: yes (`pip install llm-shelter`)
- **What works**: Full pipeline architecture, 6 validators (PII, injection, toxicity, length, schema, rules), FastAPI middleware, function decorators, CLI (scan, batch, report), zero-dependency core
- **Known limitations**: PII detection is regex-only (no NLP/ML). Toxicity is keyword-based (no embeddings). Token estimation is a simple heuristic (len/4).
- **Roadmap (v0.2)**: Rate limiting validator, custom regex patterns, OWASP LLM Top 10 checklist, Flask middleware

## Development Guide

```bash
git clone https://github.com/manasvardhan/llm-shelter.git
cd llm-shelter
pip install -e ".[dev]"
pytest
```

- **Build system**: Hatchling
- **Source layout**: `src/llm_shelter/`
- **Adding a new validator**: Create file in `validators/`, implement the `Validator` protocol (need `.name` and `.validate(text) -> ValidationResult`), re-export in `validators/__init__.py` and `__init__.py`
- **Adding a new PII pattern**: Create a `PIIPattern` dataclass in `validators/pii.py`, add to `DEFAULT_PATTERNS`
- **Adding a new injection pattern**: Create an `InjectionPattern` in `validators/injection.py`, add to appropriate list
- **Code style**: Ruff, line length 100, target Python 3.10. Mypy strict mode.

## Git Conventions

- **Branch**: main
- **Commits**: Imperative style ("Add feature X", "Fix bug Y")
- Never use em dashes in commit messages or docs

## Context

- **Author**: Manas Vardhan (ManasVardhan on GitHub)
- **Part of**: A suite of AI agent tooling
- **Related repos**: llm-cost-guardian (cost tracking), agent-sentry (crash reporting), agent-replay (trace debugging), promptdiff (prompt versioning), mcp-forge (MCP server scaffolding), bench-my-llm (benchmarking)
- **PyPI package**: `llm-shelter`
