"""llm-shelter: Safety and guardrails toolkit for LLM applications.

Provides composable validators for detecting PII, prompt injection,
toxicity, length violations, and schema conformance in LLM inputs
and outputs. Validators can be chained via :class:`GuardrailPipeline`
to build layered safety checks.

Quick start::

    from llm_shelter import GuardrailPipeline, PIIValidator, InjectionValidator
    from llm_shelter.pipeline import Action

    pipeline = GuardrailPipeline()
    pipeline.add(PIIValidator(redact=True), Action.REDACT)
    pipeline.add(InjectionValidator(), Action.BLOCK)
    result = pipeline.run("Contact me at user@example.com")
"""

from __future__ import annotations

__version__ = "0.1.1"

from llm_shelter.pipeline import GuardrailPipeline, ValidationResult
from llm_shelter.validators.pii import PIIValidator
from llm_shelter.validators.injection import InjectionValidator
from llm_shelter.validators.toxicity import ToxicityValidator
from llm_shelter.validators.length import LengthValidator
from llm_shelter.validators.schema import SchemaValidator
from llm_shelter.validators.rules import Rule, RuleValidator

__all__ = [
    "GuardrailPipeline",
    "ValidationResult",
    "PIIValidator",
    "InjectionValidator",
    "ToxicityValidator",
    "LengthValidator",
    "SchemaValidator",
    "Rule",
    "RuleValidator",
]
