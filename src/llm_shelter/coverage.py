"""Guardrail coverage reports: replay a corpus through a pipeline.

`run_coverage` feeds every sample in a corpus of prompts or responses
through a :class:`~llm_shelter.pipeline.GuardrailPipeline` and reports
which validators fired, per-category hit counts, how samples were
handled (blocked, redacted, warned, clean), which configured validators
never fired on the corpus, and which automated OWASP LLM Top 10 checks
the pipeline fails outright.

The result renders as JSON (`CoverageReport.to_dict`) or markdown
(`render_markdown`) so CI can archive it as an artifact or post it on a
pull request. The `llm-shelter coverage` CLI wraps the same engine.

Corpus format: a plain text file with one sample per line, or a JSONL
file where each line is either a JSON string or an object with a
``"text"`` field (extra fields are ignored).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from llm_shelter.owasp import audit_pipeline
from llm_shelter.pipeline import Action, GuardrailPipeline


class CoverageError(Exception):
    """Raised for unreadable or empty corpora."""


@dataclass
class ValidatorCoverage:
    """Coverage stats for one configured validator.

    Attributes:
        name: Validator name as reported in findings (e.g. ``"pii"``).
        actions: Configured actions for this validator, sorted (a name
            can appear in the pipeline more than once).
        samples_hit: Number of samples in which this validator produced
            at least one finding.
        findings: Total findings across all samples.
        categories: Finding counts keyed by category (e.g. ``"email"``).
    """

    name: str
    actions: list[str]
    samples_hit: int = 0
    findings: int = 0
    categories: dict[str, int] = field(default_factory=dict)

    def hit_rate(self, total_samples: int) -> float:
        """Fraction of samples this validator fired on (0.0 to 1.0)."""
        if total_samples == 0:
            return 0.0
        return self.samples_hit / total_samples

    def to_dict(self, total_samples: int) -> dict[str, Any]:
        return {
            "name": self.name,
            "actions": self.actions,
            "samples_hit": self.samples_hit,
            "findings": self.findings,
            "hit_rate": round(self.hit_rate(total_samples), 4),
            "categories": dict(sorted(self.categories.items())),
        }


@dataclass
class CoverageReport:
    """Aggregated outcome of replaying a corpus through a pipeline."""

    total_samples: int = 0
    blocked: int = 0
    redacted: int = 0
    warned: int = 0
    clean: int = 0
    validators: list[ValidatorCoverage] = field(default_factory=list)
    owasp_gaps: list[dict[str, str]] = field(default_factory=list)

    @property
    def unused_validators(self) -> list[str]:
        """Names of configured validators that never fired on the corpus."""
        return [v.name for v in self.validators if v.samples_hit == 0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "samples": {
                "blocked": self.blocked,
                "redacted": self.redacted,
                "warned": self.warned,
                "clean": self.clean,
            },
            "validators": [v.to_dict(self.total_samples) for v in self.validators],
            "unused_validators": self.unused_validators,
            "owasp_gaps": self.owasp_gaps,
        }


def load_corpus(path: str | Path) -> list[str]:
    """Load a corpus of samples from a text or JSONL file.

    ``.jsonl`` / ``.ndjson`` files are parsed line by line: each line is
    a JSON string or an object with a ``"text"`` field. Any other file
    is read as plain text with one sample per line. Blank lines are
    skipped in both formats.

    Raises:
        CoverageError: If the file cannot be read, a JSONL line is
            invalid, or the corpus contains no samples.
    """
    path = Path(path)
    try:
        raw = path.read_text()
    except OSError as exc:
        raise CoverageError(f"Cannot read corpus {path}: {exc}") from exc

    samples: list[str] = []
    if path.suffix.lower() in (".jsonl", ".ndjson"):
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CoverageError(
                    f"{path}:{lineno}: invalid JSON: {exc}"
                ) from exc
            if isinstance(item, str):
                samples.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                samples.append(item["text"])
            else:
                raise CoverageError(
                    f"{path}:{lineno}: expected a JSON string or an object "
                    f'with a "text" field'
                )
    else:
        samples = [line for line in raw.splitlines() if line.strip()]

    if not samples:
        raise CoverageError(f"Corpus {path} contains no samples")
    return samples


def run_coverage(pipeline: GuardrailPipeline, samples: Iterable[str]) -> CoverageReport:
    """Replay *samples* through *pipeline* and aggregate coverage stats.

    Each sample is run independently through ``pipeline.run``. Because
    the pipeline short-circuits on BLOCK, validators placed after a
    blocking one are not exercised on blocked samples, exactly as in
    production.

    Args:
        pipeline: The configured guardrail pipeline to measure.
        samples: The corpus of prompts or responses to replay.

    Returns:
        A :class:`CoverageReport` with per-validator and per-category
        hit counts, sample outcomes, unused validators, and failed
        automated OWASP checks.
    """
    coverage: dict[str, ValidatorCoverage] = {}
    for validator, action in pipeline.validators:
        entry = coverage.setdefault(
            validator.name, ValidatorCoverage(name=validator.name, actions=[])
        )
        if action.value not in entry.actions:
            entry.actions.append(action.value)
    for entry in coverage.values():
        entry.actions.sort()

    report = CoverageReport(validators=list(coverage.values()))

    for sample in samples:
        report.total_samples += 1
        result = pipeline.run(sample)
        if result.action_taken == Action.BLOCK:
            report.blocked += 1
        elif result.action_taken == Action.REDACT:
            report.redacted += 1
        elif result.action_taken == Action.WARN:
            report.warned += 1
        else:
            report.clean += 1

        per_validator: Counter[str] = Counter()
        for finding in result.findings:
            per_validator[finding.validator] += 1
            hit = coverage.get(finding.validator)
            if hit is None:
                # Defensive: findings from validators not in the pipeline
                # configuration (should not happen) still get counted.
                hit = ValidatorCoverage(name=finding.validator, actions=[])
                coverage[finding.validator] = hit
                report.validators.append(hit)
            hit.findings += 1
            hit.categories[finding.category] = (
                hit.categories.get(finding.category, 0) + 1
            )
        for name in per_validator:
            coverage[name].samples_hit += 1

    audit = audit_pipeline(pipeline)
    report.owasp_gaps = [
        {
            "id": check.check_id,
            "title": check.title,
            "remediation": check.remediation,
        }
        for check in audit.failed
    ]
    return report


def render_markdown(report: CoverageReport) -> str:
    """Render a coverage report as markdown for CI artifacts and PR comments."""
    lines = [
        "# Guardrail Coverage Report",
        "",
        (
            f"Replayed **{report.total_samples}** sample(s): "
            f"{report.blocked} blocked, {report.redacted} redacted, "
            f"{report.warned} warned, {report.clean} clean."
        ),
        "",
        "## Validators",
        "",
        "| Validator | Actions | Samples hit | Hit rate | Findings |",
        "|-----------|---------|-------------|----------|----------|",
    ]
    for v in report.validators:
        rate = f"{v.hit_rate(report.total_samples) * 100:.1f}%"
        actions = ", ".join(v.actions) if v.actions else "-"
        lines.append(
            f"| {v.name} | {actions} | {v.samples_hit} | {rate} | {v.findings} |"
        )

    fired = [v for v in report.validators if v.categories]
    if fired:
        lines += ["", "## Categories", ""]
        for v in fired:
            for category, count in sorted(v.categories.items()):
                lines.append(f"- `{v.name}/{category}`: {count}")

    unused = report.unused_validators
    if unused:
        lines += [
            "",
            "## Unused validators",
            "",
            (
                "These validators never fired on this corpus. Either the corpus "
                "lacks samples that exercise them, or they are dead weight:"
            ),
            "",
        ]
        lines += [f"- `{name}`" for name in unused]

    if report.owasp_gaps:
        lines += ["", "## OWASP gaps", ""]
        for gap in report.owasp_gaps:
            lines.append(f"- **{gap['id']} {gap['title']}**: {gap['remediation']}")
    else:
        lines += ["", "No automated OWASP LLM Top 10 checks fail for this pipeline."]

    return "\n".join(lines) + "\n"
