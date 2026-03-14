"""Token and character length limit validators.

Provides a simple guard against excessively long inputs that could
inflate costs or abuse context windows. Token estimation uses a
character-based heuristic; for precise counts, subclass and override
:meth:`LengthValidator.estimate_tokens`.
"""

from __future__ import annotations

from llm_shelter.pipeline import Action, Finding, ValidationResult


class LengthValidator:
    """Enforce character and estimated token length limits.

    Token estimation uses a simple word-split heuristic (~0.75 tokens per char
    for English). For precise counts, override ``count_tokens``.

    Args:
        max_chars: Maximum character count (None = no limit).
        max_tokens: Maximum estimated token count (None = no limit).
        action: Action to take when limit is exceeded.
    """

    name: str = "length"

    def __init__(
        self,
        max_chars: int | None = None,
        max_tokens: int | None = None,
        action: Action = Action.BLOCK,
    ) -> None:
        self.max_chars = max_chars
        self.max_tokens = max_tokens
        self.action = action

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estimate the number of tokens in *text*.

        Uses a simple heuristic of approximately 4 characters per token,
        which is reasonable for English prose. Override this method to
        plug in a tokeniser (e.g. ``tiktoken``).

        Args:
            text: The string to estimate tokens for.

        Returns:
            Estimated token count (minimum 1).
        """
        return max(1, int(len(text) / 4))

    def validate(self, text: str) -> ValidationResult:
        """Check whether *text* exceeds configured length limits.

        Args:
            text: The input string to validate.

        Returns:
            A :class:`~llm_shelter.pipeline.ValidationResult` with findings
            for each exceeded limit.
        """
        findings: list[Finding] = []

        if self.max_chars is not None and len(text) > self.max_chars:
            findings.append(
                Finding(
                    validator=self.name,
                    category="max_chars",
                    description=f"Text length {len(text)} exceeds limit of {self.max_chars} chars",
                    severity=0.8,
                )
            )

        if self.max_tokens is not None:
            est = self.estimate_tokens(text)
            if est > self.max_tokens:
                findings.append(
                    Finding(
                        validator=self.name,
                        category="max_tokens",
                        description=f"Estimated {est} tokens exceeds limit of {self.max_tokens}",
                        severity=0.8,
                    )
                )

        return ValidationResult(
            is_valid=len(findings) == 0,
            text=text,
            original_text=text,
            findings=findings,
            action_taken=self.action if findings else Action.PASSTHROUGH,
        )
