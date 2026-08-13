"""Policy files: declare a full guardrail pipeline in YAML or JSON.

A policy file describes which validators run, in what order, with which
actions and settings. Teams can review one policy file and share it
across every service instead of duplicating pipeline setup code.

Example policy (YAML)::

    version: 1
    audit_log: guardrails.jsonl
    validators:
      - type: pii
        action: redact
      - type: secrets
        action: redact
      - type: injection
        action: block
        threshold: 0.5
      - type: toxicity
        action: warn
      - type: length
        action: block
        max_chars: 8000
      - type: regex
        action: redact
        patterns:
          - name: employee_id
            regex: "EMP-\\\\d{5}"

Load it with :meth:`llm_shelter.GuardrailPipeline.from_policy` or the
CLI ``--policy`` flag. JSON policies always work; YAML policies need
``pyyaml`` (``pip install llm-shelter[policy]``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from llm_shelter.pipeline import Action, GuardrailPipeline
from llm_shelter.validators.injection import InjectionValidator
from llm_shelter.validators.length import LengthValidator
from llm_shelter.validators.pii import PIIValidator
from llm_shelter.validators.ratelimit import RateLimitValidator
from llm_shelter.validators.regex import RegexValidator, compile_pattern
from llm_shelter.validators.schema import SchemaValidator
from llm_shelter.validators.secrets import SecretsValidator
from llm_shelter.validators.toxicity import ToxicityValidator

SUPPORTED_TYPES = (
    "pii",
    "injection",
    "toxicity",
    "secrets",
    "length",
    "regex",
    "ratelimit",
    "schema",
)

_ALLOWED_KEYS: dict[str, set[str]] = {
    "pii": {"redact"},
    "injection": {"threshold"},
    "toxicity": {"threshold"},
    "secrets": {"redact"},
    "length": {"max_chars", "max_tokens"},
    "regex": {"patterns", "redact"},
    "ratelimit": {"max_requests", "window_seconds", "key"},
    "schema": {"schema"},
}

_DEFAULT_ACTIONS: dict[str, Action] = {
    "pii": Action.REDACT,
    "injection": Action.BLOCK,
    "toxicity": Action.BLOCK,
    "secrets": Action.REDACT,
    "length": Action.BLOCK,
    "regex": Action.REDACT,
    "ratelimit": Action.BLOCK,
    "schema": Action.BLOCK,
}


class PolicyError(ValueError):
    """Raised when a policy file cannot be parsed or is invalid."""


def load_policy_data(path: str | Path) -> dict[str, Any]:
    """Read and parse a policy file into a plain dict.

    ``.json`` files are parsed with the standard library. ``.yaml`` and
    ``.yml`` files require ``pyyaml``. Any other extension is tried as
    JSON first, then YAML when available.

    Args:
        path: Path to the policy file.

    Returns:
        The parsed policy mapping.

    Raises:
        PolicyError: If the file is missing, unparseable, or a YAML file
            is given without ``pyyaml`` installed.
    """
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"Policy file not found: {p}")
    raw = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()

    if suffix == ".json":
        data = _parse_json(raw, p)
    elif suffix in (".yaml", ".yml"):
        data = _parse_yaml(raw, p)
    else:
        try:
            data = _parse_json(raw, p)
        except PolicyError:
            data = _parse_yaml(raw, p)

    if not isinstance(data, dict):
        raise PolicyError(f"Policy root must be a mapping, got {type(data).__name__} in {p}")
    return data


def _parse_json(raw: str, p: Path) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"Invalid JSON in policy file {p}: {exc}") from exc


def _parse_yaml(raw: str, p: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise PolicyError(
            f"YAML policy file {p} requires pyyaml. "
            "Install it with: pip install llm-shelter[policy]"
        ) from exc
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in policy file {p}: {exc}") from exc


def build_pipeline(policy: dict[str, Any]) -> GuardrailPipeline:
    """Build a :class:`GuardrailPipeline` from a parsed policy mapping.

    Args:
        policy: Policy data, typically from :func:`load_policy_data`.

    Returns:
        A configured pipeline with validators in policy order.

    Raises:
        PolicyError: If the policy structure, a validator type, an
            action, or a setting is invalid.
    """
    version = policy.get("version", 1)
    if version != 1:
        raise PolicyError(f"Unsupported policy version: {version} (expected 1)")

    known_top = {"version", "audit_log", "validators"}
    unknown_top = set(policy) - known_top
    if unknown_top:
        raise PolicyError(f"Unknown top-level policy keys: {', '.join(sorted(unknown_top))}")

    entries = policy.get("validators")
    if not isinstance(entries, list) or not entries:
        raise PolicyError("Policy must define a non-empty 'validators' list")

    audit = None
    audit_log = policy.get("audit_log")
    if audit_log is not None:
        if not isinstance(audit_log, str) or not audit_log.strip():
            raise PolicyError("'audit_log' must be a non-empty file path string")
        from llm_shelter.auditlog import AuditLogger

        audit = AuditLogger(audit_log)

    pipeline = GuardrailPipeline(audit=audit)
    for i, entry in enumerate(entries):
        validator, action = _build_validator(entry, i)
        pipeline.add(validator, action)
    return pipeline


def _build_validator(entry: Any, index: int) -> tuple[Any, Action]:
    """Build one (validator, action) pair from a policy entry."""
    where = f"validators[{index}]"
    if not isinstance(entry, dict):
        raise PolicyError(f"{where}: each validator entry must be a mapping")

    vtype = entry.get("type")
    if not isinstance(vtype, str) or vtype not in SUPPORTED_TYPES:
        raise PolicyError(
            f"{where}: unknown validator type {vtype!r}. "
            f"Supported types: {', '.join(SUPPORTED_TYPES)}"
        )

    unknown = set(entry) - _ALLOWED_KEYS[vtype] - {"type", "action"}
    if unknown:
        raise PolicyError(
            f"{where} ({vtype}): unknown keys: {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(_ALLOWED_KEYS[vtype] | {'type', 'action'}))}"
        )

    action_raw = entry.get("action", _DEFAULT_ACTIONS[vtype].value)
    try:
        action = Action(str(action_raw).lower())
    except ValueError as exc:
        raise PolicyError(
            f"{where} ({vtype}): invalid action {action_raw!r}. "
            "Allowed: block, warn, redact"
        ) from exc
    if action == Action.PASSTHROUGH:
        raise PolicyError(f"{where} ({vtype}): action 'passthrough' is not allowed in policies")

    try:
        validator = _construct(vtype, entry, where)
    except PolicyError:
        raise
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"{where} ({vtype}): {exc}") from exc
    return validator, action


def _construct(vtype: str, entry: dict[str, Any], where: str) -> Any:
    if vtype == "pii":
        return PIIValidator(redact=bool(entry.get("redact", True)))
    if vtype == "injection":
        return InjectionValidator(threshold=float(entry.get("threshold", 0.5)))
    if vtype == "toxicity":
        return ToxicityValidator(threshold=float(entry.get("threshold", 0.5)))
    if vtype == "secrets":
        return SecretsValidator(redact=bool(entry.get("redact", True)))
    if vtype == "length":
        max_chars = entry.get("max_chars")
        max_tokens = entry.get("max_tokens")
        if max_chars is None and max_tokens is None:
            raise PolicyError(f"{where} (length): set 'max_chars' and/or 'max_tokens'")
        return LengthValidator(
            max_chars=int(max_chars) if max_chars is not None else None,
            max_tokens=int(max_tokens) if max_tokens is not None else None,
        )
    if vtype == "regex":
        raw_patterns = entry.get("patterns")
        if not isinstance(raw_patterns, list) or not raw_patterns:
            raise PolicyError(f"{where} (regex): 'patterns' must be a non-empty list")
        patterns = []
        for j, spec in enumerate(raw_patterns):
            if not isinstance(spec, dict) or "name" not in spec or "regex" not in spec:
                raise PolicyError(
                    f"{where} (regex): patterns[{j}] must be a mapping with 'name' and 'regex'"
                )
            extra = set(spec) - {"name", "regex", "placeholder", "severity"}
            if extra:
                raise PolicyError(
                    f"{where} (regex): patterns[{j}] unknown keys: {', '.join(sorted(extra))}"
                )
            patterns.append(
                compile_pattern(
                    name=str(spec["name"]),
                    regex=str(spec["regex"]),
                    placeholder=str(spec.get("placeholder", "")),
                    severity=float(spec.get("severity", 0.8)),
                )
            )
        return RegexValidator(patterns=patterns, redact=bool(entry.get("redact", True)))
    if vtype == "ratelimit":
        return RateLimitValidator(
            max_requests=int(entry.get("max_requests", 60)),
            window_seconds=float(entry.get("window_seconds", 60.0)),
            key=str(entry.get("key", "global")),
        )
    if vtype == "schema":
        schema = entry.get("schema")
        if not isinstance(schema, dict):
            raise PolicyError(f"{where} (schema): 'schema' must be a mapping")
        return SchemaValidator(schema=schema)
    raise PolicyError(f"{where}: unknown validator type {vtype!r}")  # pragma: no cover


def load_pipeline(path: str | Path) -> GuardrailPipeline:
    """Load a policy file and build its pipeline in one step.

    Args:
        path: Path to a YAML or JSON policy file.

    Returns:
        The configured :class:`GuardrailPipeline`.

    Raises:
        PolicyError: If the file cannot be read or the policy is invalid.
    """
    return build_pipeline(load_policy_data(path))


def describe_pipeline(pipeline: GuardrailPipeline) -> list[dict[str, Any]]:
    """Summarise a pipeline as a list of {validator, action} mappings.

    Useful for showing users what a policy file resolved to (the CLI
    ``policy`` command uses this).
    """
    return [
        {"validator": validator.name, "action": action.value}
        for validator, action in pipeline.validators
    ]
