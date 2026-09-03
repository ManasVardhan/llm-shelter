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

__version__ = "0.5.0"

from llm_shelter.pipeline import GuardrailPipeline, ValidationResult
from llm_shelter.streaming import StreamBlocked, StreamGuard
from llm_shelter.adapters import (
    anthropic_event_text,
    awrap_anthropic,
    awrap_openai,
    openai_chunk_text,
    wrap_anthropic,
    wrap_openai,
)
from llm_shelter.auditlog import AuditLogger, AuditRecord, iter_records, summarize
from llm_shelter.policy import PolicyError, load_pipeline, load_policy_data
from llm_shelter.plugins import (
    PluginError,
    PluginInfo,
    create_validator,
    discover_plugins,
    register_validator,
    unregister_validator,
)
from llm_shelter.owasp import CheckStatus, OwaspAudit, OwaspCheck, audit_pipeline
from llm_shelter.validators.pii import PIIValidator
from llm_shelter.validators.injection import InjectionValidator
from llm_shelter.validators.toxicity import ToxicityValidator
from llm_shelter.validators.length import LengthValidator
from llm_shelter.validators.schema import SchemaValidator
from llm_shelter.validators.secrets import SecretsValidator
from llm_shelter.validators.rules import Rule, RuleValidator
from llm_shelter.validators.ratelimit import RateLimiter, RateLimitValidator
from llm_shelter.validators.regex import RegexPattern, RegexValidator

__all__ = [
    "GuardrailPipeline",
    "ValidationResult",
    "StreamBlocked",
    "StreamGuard",
    "anthropic_event_text",
    "awrap_anthropic",
    "awrap_openai",
    "openai_chunk_text",
    "wrap_anthropic",
    "wrap_openai",
    "AuditLogger",
    "AuditRecord",
    "iter_records",
    "summarize",
    "PolicyError",
    "load_pipeline",
    "load_policy_data",
    "PluginError",
    "PluginInfo",
    "create_validator",
    "discover_plugins",
    "register_validator",
    "unregister_validator",
    "PIIValidator",
    "InjectionValidator",
    "ToxicityValidator",
    "LengthValidator",
    "SchemaValidator",
    "SecretsValidator",
    "Rule",
    "RuleValidator",
    "RateLimiter",
    "RateLimitValidator",
    "RegexPattern",
    "RegexValidator",
    "CheckStatus",
    "OwaspAudit",
    "OwaspCheck",
    "audit_pipeline",
]
