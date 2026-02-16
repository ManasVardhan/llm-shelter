"""Prompt injection detection using heuristic patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass

from llm_shelter.pipeline import Action, Finding, ValidationResult


@dataclass
class InjectionPattern:
    name: str
    pattern: re.Pattern[str]
    severity: float = 1.0


# Instruction override patterns
_OVERRIDE_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b.{0,30}"
            r"(?:previous|above|prior|all|earlier|system)\b.{0,30}"
            r"(?:instructions?|rules?|prompts?|guidelines?|constraints?)\b"
        ),
        severity=0.95,
    ),
    InjectionPattern(
        "new_instruction",
        re.compile(
            r"(?i)\b(?:you are now|from now on|new instructions?|your (?:new |real )"
            r"(?:role|instructions?|purpose|objective)|act as if)\b"
        ),
        severity=0.9,
    ),
    InjectionPattern(
        "system_prompt_extraction",
        re.compile(
            r"(?i)(?:reveal|show|print|output|display|repeat|echo|dump|leak)"
            r".{0,20}(?:system\s*prompt|initial\s*prompt|instructions?|hidden|secret)"
        ),
        severity=0.9,
    ),
]

# Delimiter / escape attacks
_DELIMITER_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        "delimiter_injection",
        re.compile(
            r"(?:```|<\|(?:im_start|im_end|system|endoftext)\|>|</?system>|"
            r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|###\s*(?:System|Human|Assistant):)"
        ),
        severity=0.95,
    ),
    InjectionPattern(
        "role_switch",
        re.compile(r"(?i)(?:^|\n)\s*(?:system|assistant|human|user)\s*:\s*\S"),
        severity=0.7,
    ),
]

# Encoding tricks
_ENCODING_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        "base64_payload",
        re.compile(
            r"(?i)(?:decode|base64|eval|execute)\s*[\(:]?\s*['\"]?"
            r"[A-Za-z0-9+/]{20,}={0,2}"
        ),
        severity=0.85,
    ),
    InjectionPattern(
        "unicode_smuggling",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{3,}"),
        severity=0.8,
    ),
    InjectionPattern(
        "hex_encoded",
        re.compile(r"(?i)(?:\\x[0-9a-f]{2}){4,}"),
        severity=0.7,
    ),
]

ALL_INJECTION_PATTERNS = _OVERRIDE_PATTERNS + _DELIMITER_PATTERNS + _ENCODING_PATTERNS


class InjectionValidator:
    """Detect potential prompt injection attacks.

    Args:
        patterns: Custom patterns to use. Defaults to all built-in patterns.
        threshold: Minimum severity to flag (0.0 to 1.0).
        action: Action when injection is detected.
    """

    name: str = "injection"

    def __init__(
        self,
        patterns: list[InjectionPattern] | None = None,
        threshold: float = 0.5,
        action: Action = Action.BLOCK,
    ) -> None:
        self.patterns = patterns or list(ALL_INJECTION_PATTERNS)
        self.threshold = threshold
        self.action = action

    def validate(self, text: str) -> ValidationResult:
        findings: list[Finding] = []

        for inj in self.patterns:
            for match in inj.pattern.finditer(text):
                if inj.severity >= self.threshold:
                    findings.append(
                        Finding(
                            validator=self.name,
                            category=inj.name,
                            description=f"Potential injection ({inj.name}): "
                            f"'{match.group()[:50]}...'",
                            span=(match.start(), match.end()),
                            severity=inj.severity,
                        )
                    )

        return ValidationResult(
            is_valid=len(findings) == 0,
            text=text,
            original_text=text,
            findings=findings,
            action_taken=self.action if findings else Action.PASSTHROUGH,
        )
