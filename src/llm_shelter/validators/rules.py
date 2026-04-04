"""Custom rule-based validator for simple user-defined checks.

Lets users define lightweight validation rules without writing a full
validator subclass. Each rule is a callable that returns ``True`` when
the text violates the rule (i.e., the text is unsafe).

Example::

    from llm_shelter.validators.rules import RuleValidator, Rule

    rules = [
        Rule("no_urls", lambda t: "http" in t.lower(), "Text contains URLs"),
        Rule("min_length", lambda t: len(t) < 10, "Text too short", severity=0.5),
    ]
    validator = RuleValidator(rules=rules)
    result = validator.validate("Visit http://evil.com")
    assert not result.is_valid
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from llm_shelter.pipeline import Action, Finding, ValidationResult


@dataclass
class Rule:
    """A single validation rule.

    Attributes:
        name: Short identifier for the rule.
        check: A callable that takes a string and returns ``True``
            when the text *violates* the rule (is unsafe).
        description: Human-readable description shown in findings.
        severity: Severity score from 0.0 to 1.0.
        category: Optional category grouping. Defaults to the rule name.
    """

    name: str
    check: Callable[[str], bool]
    description: str = ""
    severity: float = 0.8
    category: str = ""

    def __post_init__(self) -> None:
        if not self.category:
            self.category = self.name
        if not self.description:
            self.description = f"Rule '{self.name}' violated"


class RuleValidator:
    """Validate text against a list of custom rules.

    Each :class:`Rule` defines a check function. When the check returns
    ``True``, the text is considered to violate that rule and a finding
    is recorded.

    Args:
        rules: List of :class:`Rule` instances to evaluate.
        action: Default action when any rule is violated.
    """

    name: str = "rules"

    def __init__(
        self,
        rules: list[Rule] | None = None,
        action: Action = Action.BLOCK,
    ) -> None:
        self.rules = rules or []
        self.action = action

    def add_rule(self, rule: Rule) -> "RuleValidator":
        """Add a rule to the validator. Returns self for chaining."""
        self.rules.append(rule)
        return self

    def validate(self, text: str) -> ValidationResult:
        """Run *text* through all configured rules.

        Args:
            text: The input string to validate.

        Returns:
            A :class:`~llm_shelter.pipeline.ValidationResult` with one
            finding per violated rule.
        """
        findings: list[Finding] = []

        for rule in self.rules:
            try:
                violated = rule.check(text)
            except Exception:
                # If a rule's check raises, treat it as not violated
                # to avoid blocking on buggy user rules
                continue

            if violated:
                findings.append(
                    Finding(
                        validator=self.name,
                        category=rule.category,
                        description=rule.description,
                        severity=rule.severity,
                    )
                )

        return ValidationResult(
            is_valid=len(findings) == 0,
            text=text,
            original_text=text,
            findings=findings,
            action_taken=self.action if findings else Action.PASSTHROUGH,
        )
