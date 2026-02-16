"""PII detection and redaction using regex patterns (no spaCy dependency)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from llm_shelter.pipeline import Action, Finding, ValidationResult


@dataclass
class PIIPattern:
    """A named regex pattern for PII detection."""
    name: str
    pattern: re.Pattern[str]
    placeholder: str
    severity: float = 1.0


# --- Patterns ---

_EMAIL = PIIPattern(
    name="email",
    pattern=re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    placeholder="[EMAIL_REDACTED]",
    severity=0.8,
)

_PHONE_US = PIIPattern(
    name="phone",
    pattern=re.compile(
        r"(?<!\d)"
        r"(?:\+?1[\s.\-]?)?"
        r"(?:\(?\d{3}\)?[\s.\-]?)"
        r"\d{3}[\s.\-]?\d{4}"
        r"(?!\d)"
    ),
    placeholder="[PHONE_REDACTED]",
    severity=0.8,
)

_SSN = PIIPattern(
    name="ssn",
    pattern=re.compile(
        r"\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b"
    ),
    placeholder="[SSN_REDACTED]",
    severity=1.0,
)

_CREDIT_CARD = PIIPattern(
    name="credit_card",
    pattern=re.compile(
        r"\b"
        r"(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"  # Visa/MC/Amex/Discover
        r"[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4}"
        r"\b"
    ),
    placeholder="[CREDIT_CARD_REDACTED]",
    severity=1.0,
)

_IP_ADDRESS = PIIPattern(
    name="ip_address",
    pattern=re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    placeholder="[IP_REDACTED]",
    severity=0.5,
)

_AWS_KEY = PIIPattern(
    name="aws_access_key",
    pattern=re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    placeholder="[AWS_KEY_REDACTED]",
    severity=1.0,
)

DEFAULT_PATTERNS: list[PIIPattern] = [_EMAIL, _PHONE_US, _SSN, _CREDIT_CARD, _IP_ADDRESS, _AWS_KEY]


class PIIValidator:
    """Detect and optionally redact PII from text.

    Args:
        patterns: List of PIIPattern to check. Defaults to all built-in patterns.
        redact: If True, replace matches with placeholders in the returned text.
        action: Default action when PII is found.
    """

    name: str = "pii"

    def __init__(
        self,
        patterns: list[PIIPattern] | None = None,
        redact: bool = True,
        action: Action = Action.REDACT,
    ) -> None:
        self.patterns = patterns or list(DEFAULT_PATTERNS)
        self.redact = redact
        self.action = action

    def validate(self, text: str) -> ValidationResult:
        findings: list[Finding] = []
        redacted = text

        for pii in self.patterns:
            for match in pii.pattern.finditer(text):
                findings.append(Finding(
                    validator=self.name,
                    category=pii.name,
                    description=f"Detected {pii.name}: {match.group()[:4]}***",
                    span=(match.start(), match.end()),
                    severity=pii.severity,
                    redacted_value=pii.placeholder,
                ))

        if self.redact and findings:
            # Redact from right to left to preserve span positions
            sorted_findings = sorted(findings, key=lambda f: f.span[0] if f.span else 0, reverse=True)
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
