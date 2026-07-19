"""Custom regex pattern validator for domain-specific detection.

Lets users define their own named regex rules for PII or sensitive
content that the built-in validators do not cover (employee IDs,
internal ticket numbers, project codenames, customer references).
Patterns can be built programmatically with :class:`RegexPattern` or
parsed from compact ``LABEL=REGEX`` specs (used by the CLI ``-p`` flag).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from llm_shelter.pipeline import Action, Finding, ValidationResult


@dataclass
class RegexPattern:
    """A named user-defined regex rule.

    Attributes:
        name: Label reported as the finding category (e.g. ``"employee_id"``).
        pattern: Compiled regular expression to search for.
        placeholder: Replacement text used when redacting. Defaults to
            ``[NAME_REDACTED]`` derived from ``name``.
        severity: Severity score between 0.0 and 1.0.
    """

    name: str
    pattern: re.Pattern[str]
    placeholder: str = ""
    severity: float = 0.8

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("RegexPattern name must be a non-empty string")
        self.name = self.name.strip()
        if not self.placeholder:
            safe = re.sub(r"[^A-Za-z0-9]+", "_", self.name).strip("_").upper() or "CUSTOM"
            self.placeholder = f"[{safe}_REDACTED]"
        if not 0.0 <= self.severity <= 1.0:
            raise ValueError(f"severity must be between 0.0 and 1.0, got {self.severity}")


def compile_pattern(
    name: str,
    regex: str,
    placeholder: str = "",
    severity: float = 0.8,
    flags: int = 0,
) -> RegexPattern:
    """Compile a regex string into a :class:`RegexPattern`.

    Args:
        name: Label for the rule.
        regex: Regular expression source string.
        placeholder: Optional custom redaction placeholder.
        severity: Severity score between 0.0 and 1.0.
        flags: Optional ``re`` module flags (e.g. ``re.IGNORECASE``).

    Returns:
        A ready-to-use :class:`RegexPattern`.

    Raises:
        ValueError: If the regex does not compile or the name is empty.
    """
    try:
        compiled = re.compile(regex, flags)
    except re.error as exc:
        raise ValueError(f"Invalid regex for pattern '{name}': {exc}") from exc
    return RegexPattern(name=name, pattern=compiled, placeholder=placeholder, severity=severity)


def parse_pattern_spec(spec: str) -> RegexPattern:
    """Parse a compact ``LABEL=REGEX`` spec into a :class:`RegexPattern`.

    The label may not contain ``=``; everything after the first ``=`` is
    treated as the regex, so regexes containing ``=`` work unquoted.

    Args:
        spec: A string like ``"employee_id=EMP-\\d{5}"``.

    Returns:
        The parsed :class:`RegexPattern`.

    Raises:
        ValueError: If the spec has no ``=``, an empty label, an empty
            regex, or the regex does not compile.
    """
    label, sep, regex = spec.partition("=")
    label = label.strip()
    if not sep:
        raise ValueError(f"Invalid pattern spec '{spec}': expected LABEL=REGEX")
    if not label:
        raise ValueError(f"Invalid pattern spec '{spec}': label is empty")
    if not regex:
        raise ValueError(f"Invalid pattern spec '{spec}': regex is empty")
    return compile_pattern(label, regex)


class RegexValidator:
    """Detect and optionally redact matches of user-defined regex rules.

    Fits the :class:`~llm_shelter.pipeline.Validator` protocol so it can
    be chained in a :class:`~llm_shelter.pipeline.GuardrailPipeline` with
    BLOCK, WARN, or REDACT actions.

    Example::

        validator = RegexValidator.from_specs(["employee_id=EMP-\\d{5}"])
        result = validator.validate("Contact EMP-12345 for access")

    Args:
        patterns: List of :class:`RegexPattern` rules to apply.
        redact: If True, replace matches with placeholders in ``result.text``.
        action: Default action reported when matches are found.
    """

    name: str = "regex"

    def __init__(
        self,
        patterns: list[RegexPattern],
        redact: bool = True,
        action: Action = Action.REDACT,
    ) -> None:
        if not patterns:
            raise ValueError("RegexValidator requires at least one pattern")
        self.patterns = list(patterns)
        self.redact = redact
        self.action = action

    @classmethod
    def from_specs(
        cls,
        specs: list[str],
        redact: bool = True,
        action: Action = Action.REDACT,
    ) -> RegexValidator:
        """Build a validator from compact ``LABEL=REGEX`` spec strings.

        Args:
            specs: Spec strings, e.g. ``["ticket=JIRA-\\d+", "codename=(?i)phoenix"]``.
            redact: Passed through to the constructor.
            action: Passed through to the constructor.

        Returns:
            A configured :class:`RegexValidator`.

        Raises:
            ValueError: If ``specs`` is empty or any spec is invalid.
        """
        if not specs:
            raise ValueError("from_specs requires at least one LABEL=REGEX spec")
        return cls([parse_pattern_spec(s) for s in specs], redact=redact, action=action)

    def validate(self, text: str) -> ValidationResult:
        """Scan *text* against all custom patterns.

        Args:
            text: The input string to scan.

        Returns:
            A :class:`~llm_shelter.pipeline.ValidationResult`. When
            ``redact`` is enabled, ``result.text`` has matches replaced
            with each pattern's placeholder.
        """
        findings: list[Finding] = []
        redacted = text

        for rule in self.patterns:
            for match in rule.pattern.finditer(text):
                if match.start() == match.end():
                    continue  # Skip zero-width matches to avoid useless findings
                snippet = match.group()[:4]
                findings.append(
                    Finding(
                        validator=self.name,
                        category=rule.name,
                        description=f"Matched custom pattern {rule.name}: {snippet}***",
                        span=(match.start(), match.end()),
                        severity=rule.severity,
                        redacted_value=rule.placeholder,
                    )
                )

        if self.redact and findings:
            # Redact from right to left to preserve span positions
            sorted_findings = sorted(
                findings, key=lambda f: f.span[0] if f.span else 0, reverse=True
            )
            for f in sorted_findings:
                if f.span and f.redacted_value:
                    redacted = redacted[: f.span[0]] + f.redacted_value + redacted[f.span[1] :]

        return ValidationResult(
            is_valid=len(findings) == 0,
            text=redacted,
            original_text=text,
            findings=findings,
            action_taken=self.action if findings else Action.PASSTHROUGH,
        )


__all__ = [
    "RegexPattern",
    "RegexValidator",
    "compile_pattern",
    "parse_pattern_spec",
]
