"""Keyword and pattern-based toxicity scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass

from llm_shelter.pipeline import Action, Finding, ValidationResult


@dataclass
class ToxicityCategory:
    name: str
    patterns: list[re.Pattern[str]]
    weight: float = 1.0


_PROFANITY = ToxicityCategory(
    name="profanity",
    patterns=[
        re.compile(r"(?i)\b(?:fuck|shit|damn|ass|bitch|crap|dick|piss)\w*\b"),
    ],
    weight=0.6,
)

_SLURS = ToxicityCategory(
    name="slurs",
    patterns=[
        re.compile(r"(?i)\b(?:retard(?:ed)?|spaz|cripple)\b"),
    ],
    weight=0.8,
)

_THREATS = ToxicityCategory(
    name="threats",
    patterns=[
        re.compile(r"(?i)\b(?:i(?:'ll| will))\b.{0,20}\b(?:kill|hurt|destroy|attack|murder)\b"),
        re.compile(r"(?i)\b(?:bomb|weapon|explosive)\b.{0,20}\b(?:make|build|create|how to)\b"),
        re.compile(r"(?i)\b(?:how to)\b.{0,20}\b(?:bomb|weapon|explosive|poison|kill)\b"),
    ],
    weight=1.0,
)

_HARASSMENT = ToxicityCategory(
    name="harassment",
    patterns=[
        re.compile(r"(?i)\b(?:kys|kill\s*yourself|go\s*die)\b"),
        re.compile(r"(?i)\byou(?:'re| are)\b.{0,15}\b(?:worthless|pathetic|disgusting|ugly)\b"),
    ],
    weight=0.9,
)

DEFAULT_CATEGORIES: list[ToxicityCategory] = [_PROFANITY, _SLURS, _THREATS, _HARASSMENT]


class ToxicityValidator:
    """Score and filter text for toxic content.

    Args:
        categories: Toxicity categories to check.
        threshold: Score above which text is considered toxic (0.0 to 1.0).
        action: Action when toxicity is detected.
    """

    name: str = "toxicity"

    def __init__(
        self,
        categories: list[ToxicityCategory] | None = None,
        threshold: float = 0.5,
        action: Action = Action.BLOCK,
    ) -> None:
        self.categories = categories or list(DEFAULT_CATEGORIES)
        self.threshold = threshold
        self.action = action

    def validate(self, text: str) -> ValidationResult:
        findings: list[Finding] = []
        max_score: float = 0.0

        for cat in self.categories:
            for pattern in cat.patterns:
                for match in pattern.finditer(text):
                    score = cat.weight
                    max_score = max(max_score, score)
                    findings.append(
                        Finding(
                            validator=self.name,
                            category=cat.name,
                            description=f"Toxic content ({cat.name})",
                            span=(match.start(), match.end()),
                            severity=score,
                        )
                    )

        triggered = max_score >= self.threshold
        return ValidationResult(
            is_valid=not triggered,
            text=text,
            original_text=text,
            findings=findings if triggered else [],
            action_taken=self.action if triggered else Action.PASSTHROUGH,
        )
