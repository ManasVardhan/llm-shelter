"""Composable guardrail pipeline for chaining validators.

This module defines the core pipeline architecture: validators conforming
to the :class:`Validator` protocol are added to a :class:`GuardrailPipeline`
with an associated :class:`Action`. When :meth:`GuardrailPipeline.run` is
called, each validator runs in order. The pipeline short-circuits on
``BLOCK``, applies text modifications on ``REDACT``, and collects all
findings for ``WARN``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class Action(Enum):
    """Action to take when a validator reports findings.

    Members:
        BLOCK: Halt the pipeline immediately and mark the result as blocked.
        WARN: Record the finding but allow the text through unchanged.
        REDACT: Replace matched content with placeholders and continue.
        PASSTHROUGH: No action (used internally when no findings exist).
    """

    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"
    PASSTHROUGH = "passthrough"


@dataclass
class Finding:
    """A single finding from a validator.

    Attributes:
        validator: Name of the validator that produced this finding (e.g. ``"pii"``).
        category: Sub-category within the validator (e.g. ``"email"``, ``"ssn"``).
        description: Human-readable description of what was detected.
        span: Optional ``(start, end)`` character offsets into the original text.
        severity: Severity score between 0.0 (informational) and 1.0 (critical).
        redacted_value: Replacement placeholder used when redacting (e.g. ``"[EMAIL_REDACTED]"``).
    """

    validator: str
    category: str
    description: str
    span: tuple[int, int] | None = None
    severity: float = 1.0
    redacted_value: str | None = None


@dataclass
class ValidationResult:
    """Result from running text through a validator or pipeline.

    Attributes:
        is_valid: ``True`` when the text passed all checks (or only triggered warnings).
        text: The (potentially redacted) text after processing.
        original_text: The unmodified input text.
        findings: List of :class:`Finding` objects describing detected issues.
        action_taken: The most severe :class:`Action` applied during processing.
    """

    is_valid: bool
    text: str
    original_text: str
    findings: list[Finding] = field(default_factory=list)
    action_taken: Action = Action.PASSTHROUGH

    @property
    def blocked(self) -> bool:
        """Return ``True`` if the pipeline blocked this text."""
        return self.action_taken == Action.BLOCK

    @property
    def has_findings(self) -> bool:
        """Return ``True`` if any findings were recorded."""
        return len(self.findings) > 0


@runtime_checkable
class Validator(Protocol):
    """Protocol that all validators must satisfy.

    Any class with a ``name`` attribute and a ``validate(text) -> ValidationResult``
    method is a valid validator. No inheritance required.
    """

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
        """Add a validator to the pipeline.

        Args:
            validator: Any object satisfying the :class:`Validator` protocol.
            action: The :class:`Action` to take when this validator reports findings.

        Returns:
            ``self``, allowing fluent chaining like ``pipeline.add(A).add(B)``.
        """
        self._validators.append((validator, action))
        return self

    def run(self, text: str) -> ValidationResult:
        """Run text through all validators in sequence.

        Validators execute in the order they were added. On ``BLOCK``, the
        pipeline short-circuits immediately. On ``REDACT``, the modified text
        is forwarded to subsequent validators. On ``WARN``, the finding is
        recorded but the text passes through unchanged.

        Args:
            text: The input text to validate.

        Returns:
            A :class:`ValidationResult` summarising all findings and the
            final action taken.
        """
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
