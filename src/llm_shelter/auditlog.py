"""Structured JSONL audit logging for pipeline decisions.

Attach an :class:`AuditLogger` to a :class:`~llm_shelter.pipeline.GuardrailPipeline`
and every ``run()`` call appends one JSON line describing the decision:
which validators ran, what they found, the action taken, and latency.
The log never contains the scanned text by default, so it is safe to
keep for compliance trails.

Example::

    from llm_shelter import AuditLogger, GuardrailPipeline, PIIValidator
    from llm_shelter.pipeline import Action

    audit = AuditLogger("shelter-audit.jsonl")
    pipeline = GuardrailPipeline(audit=audit)
    pipeline.add(PIIValidator(redact=True), Action.REDACT)
    pipeline.run("my email is a@b.com", context={"user": "alice"})

Analyze a log offline with :func:`iter_records` and :func:`summarize`,
or from the terminal with ``llm-shelter audit-log shelter-audit.jsonl``.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from llm_shelter.pipeline import ValidationResult


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditRecord:
    """One pipeline decision, as written to the JSONL audit log.

    Attributes:
        timestamp: ISO 8601 UTC time of the decision.
        action: Final action taken (``block``, ``warn``, ``redact``, ``passthrough``).
        is_valid: Whether the text passed (possibly with warnings).
        blocked: Whether the pipeline blocked the text.
        input_chars: Length of the original input text.
        output_chars: Length of the (possibly redacted) output text.
        redacted: Whether the output differs from the input.
        latency_ms: Total pipeline latency in milliseconds.
        validators: Per-validator entries with name, configured action,
            findings count, and latency in milliseconds.
        findings: Flat list of findings with validator, category,
            severity, and description.
        context: Optional caller-supplied metadata (user id, request id, ...).
    """

    timestamp: str
    action: str
    is_valid: bool
    blocked: bool
    input_chars: int
    output_chars: int
    redacted: bool
    latency_ms: float
    validators: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to a plain dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditRecord":
        """Reconstruct a record from a parsed JSON object."""
        return cls(
            timestamp=data.get("timestamp", ""),
            action=data.get("action", "passthrough"),
            is_valid=bool(data.get("is_valid", True)),
            blocked=bool(data.get("blocked", False)),
            input_chars=int(data.get("input_chars", 0)),
            output_chars=int(data.get("output_chars", 0)),
            redacted=bool(data.get("redacted", False)),
            latency_ms=float(data.get("latency_ms", 0.0)),
            validators=list(data.get("validators", [])),
            findings=list(data.get("findings", [])),
            context=data.get("context"),
        )


def build_record(
    result: "ValidationResult",
    validators: list[dict[str, Any]],
    latency_ms: float,
    context: dict[str, Any] | None = None,
) -> AuditRecord:
    """Build an :class:`AuditRecord` from a pipeline result.

    Args:
        result: The :class:`~llm_shelter.pipeline.ValidationResult` to log.
        validators: Per-validator entries (name, action, findings, latency_ms).
        latency_ms: Total pipeline latency in milliseconds.
        context: Optional caller metadata to attach.
    """
    return AuditRecord(
        timestamp=_now_iso(),
        action=result.action_taken.value,
        is_valid=result.is_valid,
        blocked=result.blocked,
        input_chars=len(result.original_text),
        output_chars=len(result.text),
        redacted=result.text != result.original_text,
        latency_ms=round(latency_ms, 3),
        validators=validators,
        findings=[
            {
                "validator": f.validator,
                "category": f.category,
                "severity": f.severity,
                "description": f.description,
            }
            for f in result.findings
        ],
        context=context,
    )


class AuditLogger:
    """Thread-safe JSONL sink for pipeline decisions.

    Writes one JSON object per line to *path* (created on first write,
    parent directories included) or to an open text *stream*. Records
    never include the scanned text, only lengths, findings metadata,
    and caller-supplied context.

    Args:
        path: Path of the JSONL file to append to.
        stream: Alternatively, an open text stream to write to (takes
            precedence over *path* when both are given).
    """

    def __init__(self, path: str | Path | None = None, stream: IO[str] | None = None) -> None:
        if path is None and stream is None:
            raise ValueError("AuditLogger requires a path or a stream.")
        self.path = Path(path) if path is not None else None
        self._stream = stream
        self._lock = threading.Lock()

    def log(self, record: AuditRecord) -> None:
        """Append one record to the sink."""
        line = json.dumps(record.to_dict(), ensure_ascii=False)
        with self._lock:
            if self._stream is not None:
                self._stream.write(line + "\n")
                self._stream.flush()
            else:
                assert self.path is not None
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")


def iter_records(path: str | Path) -> Iterator[AuditRecord]:
    """Yield records from a JSONL audit log.

    Blank and malformed lines (for example a partial line from an
    interrupted write) are skipped rather than raising.
    """
    log_path = Path(path)
    if not log_path.exists():
        raise FileNotFoundError(f"Audit log '{log_path}' not found")
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                yield AuditRecord.from_dict(data)


def summarize(records: Iterator[AuditRecord] | list[AuditRecord]) -> dict[str, Any]:
    """Aggregate audit records into a summary dictionary.

    Returns a dict with total runs, counts by action, blocked count,
    total findings, findings by validator and by category, and latency
    statistics (average and max, in milliseconds).
    """
    total = 0
    blocked = 0
    by_action: dict[str, int] = {}
    findings_total = 0
    by_validator: dict[str, int] = {}
    by_category: dict[str, int] = {}
    latency_sum = 0.0
    latency_max = 0.0

    for record in records:
        total += 1
        blocked += 1 if record.blocked else 0
        by_action[record.action] = by_action.get(record.action, 0) + 1
        latency_sum += record.latency_ms
        latency_max = max(latency_max, record.latency_ms)
        for finding in record.findings:
            findings_total += 1
            validator = finding.get("validator", "unknown")
            category = finding.get("category", "unknown")
            by_validator[validator] = by_validator.get(validator, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1

    return {
        "total_runs": total,
        "blocked": blocked,
        "by_action": by_action,
        "findings_total": findings_total,
        "findings_by_validator": by_validator,
        "findings_by_category": by_category,
        "avg_latency_ms": round(latency_sum / total, 3) if total else 0.0,
        "max_latency_ms": round(latency_max, 3),
    }
