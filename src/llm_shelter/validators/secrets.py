"""Secret and credential detection using regex patterns.

Detects API keys and tokens for common providers (OpenAI, Anthropic, GitHub,
Slack, Google, Hugging Face, Stripe), JWTs, PEM private key headers, and
generic bearer tokens. All detection is regex based with no external
dependencies. Complements :class:`~llm_shelter.validators.pii.PIIValidator`,
which focuses on personal data rather than credentials.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from llm_shelter.pipeline import Action, Finding, ValidationResult


@dataclass
class SecretPattern:
    """A named regex pattern for secret detection."""

    name: str
    pattern: re.Pattern[str]
    placeholder: str
    severity: float = 1.0


# --- Patterns ---

_OPENAI_KEY = SecretPattern(
    name="openai_api_key",
    pattern=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    placeholder="[OPENAI_KEY_REDACTED]",
)

_ANTHROPIC_KEY = SecretPattern(
    name="anthropic_api_key",
    pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    placeholder="[ANTHROPIC_KEY_REDACTED]",
)

_GITHUB_TOKEN = SecretPattern(
    name="github_token",
    pattern=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    placeholder="[GITHUB_TOKEN_REDACTED]",
)

_SLACK_TOKEN = SecretPattern(
    name="slack_token",
    pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    placeholder="[SLACK_TOKEN_REDACTED]",
)

_GOOGLE_API_KEY = SecretPattern(
    name="google_api_key",
    pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    placeholder="[GOOGLE_KEY_REDACTED]",
)

_HUGGINGFACE_TOKEN = SecretPattern(
    name="huggingface_token",
    pattern=re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    placeholder="[HF_TOKEN_REDACTED]",
)

_STRIPE_KEY = SecretPattern(
    name="stripe_key",
    pattern=re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    placeholder="[STRIPE_KEY_REDACTED]",
)

_JWT = SecretPattern(
    name="jwt",
    pattern=re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    placeholder="[JWT_REDACTED]",
    severity=0.9,
)

_PRIVATE_KEY_BLOCK = SecretPattern(
    name="private_key",
    pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    placeholder="[PRIVATE_KEY_REDACTED]",
)

_BEARER_TOKEN = SecretPattern(
    name="bearer_token",
    pattern=re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-.~+/]{20,}=*"),
    placeholder="[BEARER_TOKEN_REDACTED]",
    severity=0.8,
)

DEFAULT_SECRET_PATTERNS: list[SecretPattern] = [
    _ANTHROPIC_KEY,  # before OpenAI: sk-ant- would also match the sk- pattern
    _OPENAI_KEY,
    _GITHUB_TOKEN,
    _SLACK_TOKEN,
    _GOOGLE_API_KEY,
    _HUGGINGFACE_TOKEN,
    _STRIPE_KEY,
    _JWT,
    _PRIVATE_KEY_BLOCK,
    _BEARER_TOKEN,
]


class SecretsValidator:
    """Detect and optionally redact API keys, tokens, and other credentials.

    Args:
        patterns: List of SecretPattern to check. Defaults to all built-in
            patterns.
        redact: If True, replace matches with placeholders in the returned
            text.
        action: Default action when a secret is found.

    Example::

        from llm_shelter import SecretsValidator

        result = SecretsValidator().validate("my key is sk-ant-api03-abc123def456ghi789jkl")
        assert not result.is_valid
    """

    name: str = "secrets"

    def __init__(
        self,
        patterns: list[SecretPattern] | None = None,
        redact: bool = True,
        action: Action = Action.REDACT,
    ) -> None:
        self.patterns = patterns or list(DEFAULT_SECRET_PATTERNS)
        self.redact = redact
        self.action = action

    def validate(self, text: str) -> ValidationResult:
        """Scan *text* for secrets and optionally redact matches.

        Overlapping matches from later patterns are skipped so each region of
        text is reported once (for example, an Anthropic key is not double
        reported as an OpenAI key).

        Args:
            text: The input string to scan.

        Returns:
            A :class:`~llm_shelter.pipeline.ValidationResult`. When ``redact``
            is enabled, ``result.text`` contains the redacted version.
        """
        findings: list[Finding] = []
        claimed: list[tuple[int, int]] = []
        redacted = text

        for secret in self.patterns:
            for match in secret.pattern.finditer(text):
                span = (match.start(), match.end())
                if any(span[0] < end and start < span[1] for start, end in claimed):
                    continue
                claimed.append(span)
                findings.append(
                    Finding(
                        validator=self.name,
                        category=secret.name,
                        description=f"Detected {secret.name}: {match.group()[:6]}***",
                        span=span,
                        severity=secret.severity,
                        redacted_value=secret.placeholder,
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
