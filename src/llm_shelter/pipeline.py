"""Composable guardrail pipeline for chaining validators."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class Action(Enum):
    """Action to take when validation fails."""
    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"
    PASSTHROUGH = "passthrough"


@dataclass
class Finding:
    """A single finding from a validator."""
    validator: str
    category: str
    description: str
    span: tuple[int, int] | None = None
    severity: float = 1.0
    redacted_value: str | None = None


@dataclass
class ValidationResult:
    """Result from running text through a validator or pipeline."""
    is_valid: bool
    text: str
    original_text: str
    findings: list[Finding] = field(default_factory=list)
    action_taken: Action = Action.PASSTHROUGH

    @property
    def blocked(self) -> bool:
        return self.action_taken == Action.BLOCK

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


@runtime_checkable
class Validator(Protocol):
    """Protocol for all validators."""
    name: str

    def validate(self, text: str) -> ValidationResult: ...


class GuardrailPipeline:
    """Chain multiple validators into a composable pipeline.

    Example::

        pipeline = GuardrailPipeline()
        pipeline.add(PIIValidator(action=Action.REDACT))
        pipeline.add(InjectionValidator(action=Action.BLOCK))
        result = pipeline.run("my email is test@example.com")
    """

    def __init__(self) -> None:
        self._validators: list[tuple[Validator, Action]] = []

    def add(self, validator: Validator, action: Action = Action.BLOCK) -> "GuardrailPipeline":
        """Add a validator to the pipeline. Returns self for chaining."""
        self._validators.append((validator, action))
        return self

    def run(self, text: str) -> ValidationResult:
        """Run text through all validators in order."""
        original = text
        all_findings: list[Finding] = []
        final_action = Action.PASSTHROUGH

        for validator, action in self._validators:
            result = validator.validate(text)

            if result.has_findings:
                all_findings.extend(result.findings)

                if action == Action.BLOCK:
                    return ValidationResult(
                        is_valid=False,
                        text=text,
                        original_text=original,
                        findings=all_findings,
                        action_taken=Action.BLOCK,
                    )
                elif action == Action.REDACT:
                    text = result.text
                    if final_action != Action.BLOCK:
                        final_action = Action.REDACT
                elif action == Action.WARN:
                    if final_action == Action.PASSTHROUGH:
                        final_action = Action.WARN

        is_valid = final_action in (Action.PASSTHROUGH, Action.WARN)
        return ValidationResult(
            is_valid=is_valid,
            text=text,
            original_text=original,
            findings=all_findings,
            action_taken=final_action,
        )
