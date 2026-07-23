"""OWASP Top 10 for LLM Applications checklist audit.

Maps a configured :class:`~llm_shelter.pipeline.GuardrailPipeline` to the
OWASP Top 10 for LLM Applications (LLM01-LLM10). Risks that llm-shelter
validators can mitigate are checked automatically (pass, partial, fail
based on which validators are present and how they are configured);
risks that are architectural or process-level are reported as manual
review items with remediation guidance.

Usage::

    from llm_shelter import GuardrailPipeline, InjectionValidator, PIIValidator
    from llm_shelter.pipeline import Action
    from llm_shelter.owasp import audit_pipeline

    pipeline = GuardrailPipeline()
    pipeline.add(InjectionValidator(), Action.BLOCK)
    pipeline.add(PIIValidator(redact=True), Action.REDACT)

    audit = audit_pipeline(pipeline)
    for check in audit.checks:
        print(check.check_id, check.status.value, check.title)
    print(audit.summary())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from llm_shelter.pipeline import Action, GuardrailPipeline


class CheckStatus(Enum):
    """Outcome of a single OWASP checklist item."""

    PASS = "pass"
    PARTIAL = "partial"
    FAIL = "fail"
    MANUAL = "manual"


@dataclass
class OwaspCheck:
    """One OWASP LLM Top 10 checklist item.

    Attributes:
        check_id: OWASP identifier, e.g. ``"LLM01"``.
        title: Short risk title from the OWASP list.
        status: Audit outcome for this risk.
        automated: True when llm-shelter can evaluate the risk from the
            pipeline configuration; False for manual review items.
        evidence: Human-readable notes about what was (or was not) found.
        remediation: Guidance for closing the gap.
    """

    check_id: str
    title: str
    status: CheckStatus
    automated: bool
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class OwaspAudit:
    """Full result of auditing a pipeline against the OWASP LLM Top 10."""

    checks: list[OwaspCheck] = field(default_factory=list)

    @property
    def passed(self) -> list[OwaspCheck]:
        return [c for c in self.checks if c.status == CheckStatus.PASS]

    @property
    def partial(self) -> list[OwaspCheck]:
        return [c for c in self.checks if c.status == CheckStatus.PARTIAL]

    @property
    def failed(self) -> list[OwaspCheck]:
        return [c for c in self.checks if c.status == CheckStatus.FAIL]

    @property
    def manual(self) -> list[OwaspCheck]:
        return [c for c in self.checks if c.status == CheckStatus.MANUAL]

    @property
    def has_gaps(self) -> bool:
        """True when any automated check failed outright."""
        return bool(self.failed)

    def summary(self) -> str:
        """One-line summary of the audit outcome."""
        return (
            f"{len(self.passed)} pass, {len(self.partial)} partial, "
            f"{len(self.failed)} fail, {len(self.manual)} manual review"
        )


def _entries(pipeline: GuardrailPipeline) -> list[tuple[str, Action]]:
    """Return (validator name, action) pairs from a pipeline."""
    return [(validator.name, action) for validator, action in pipeline.validators]


def _names(pipeline: GuardrailPipeline) -> set[str]:
    return {name for name, _ in _entries(pipeline)}


def _actions_for(pipeline: GuardrailPipeline, name: str) -> set[Action]:
    return {action for entry_name, action in _entries(pipeline) if entry_name == name}


def _check_llm01(pipeline: GuardrailPipeline) -> OwaspCheck:
    """LLM01 Prompt Injection: an injection validator should BLOCK."""
    check = OwaspCheck(
        check_id="LLM01",
        title="Prompt Injection",
        status=CheckStatus.FAIL,
        automated=True,
        remediation=(
            "Add InjectionValidator with Action.BLOCK to reject jailbreak and "
            "instruction-override attempts before they reach the model."
        ),
    )
    actions = _actions_for(pipeline, "injection")
    if not actions:
        check.evidence.append("No injection validator in the pipeline.")
        return check

    if Action.BLOCK in actions:
        check.status = CheckStatus.PASS
        check.evidence.append("InjectionValidator present with Action.BLOCK.")
    else:
        check.status = CheckStatus.PARTIAL
        check.evidence.append(
            "InjectionValidator present but not blocking "
            f"(action: {', '.join(sorted(a.value for a in actions))})."
        )
        check.remediation = (
            "Upgrade the injection validator to Action.BLOCK so detected "
            "injection attempts are rejected, not just logged."
        )
    return check


def _check_llm02(pipeline: GuardrailPipeline) -> OwaspCheck:
    """LLM02 Insecure Output Handling: validate model output structure/content."""
    check = OwaspCheck(
        check_id="LLM02",
        title="Insecure Output Handling",
        status=CheckStatus.FAIL,
        automated=True,
        remediation=(
            "Validate model outputs before they reach downstream systems: "
            "SchemaValidator for structured output, ToxicityValidator for "
            "harmful content, or RuleValidator for custom output rules. "
            "Always treat model output as untrusted input."
        ),
    )
    present = _names(pipeline) & {"schema", "toxicity", "rules"}
    if not present:
        check.evidence.append("No output validation (schema, toxicity, or rules) found.")
        return check

    check.evidence.append(f"Output validation present: {', '.join(sorted(present))}.")
    if "schema" in present:
        check.status = CheckStatus.PASS
    else:
        check.status = CheckStatus.PARTIAL
        check.remediation = (
            "Add SchemaValidator to enforce structured output before it is "
            "consumed by downstream code."
        )
    return check


def _check_llm04(pipeline: GuardrailPipeline) -> OwaspCheck:
    """LLM04 Model Denial of Service: rate and size limits."""
    check = OwaspCheck(
        check_id="LLM04",
        title="Model Denial of Service",
        status=CheckStatus.FAIL,
        automated=True,
        remediation=(
            "Add RateLimitValidator (per-user sliding window) and "
            "LengthValidator (max_chars) to stop request floods and "
            "oversized inputs from exhausting model capacity."
        ),
    )
    names = _names(pipeline)
    has_rate = "rate_limit" in names
    has_length = "length" in names

    if has_rate and has_length:
        check.status = CheckStatus.PASS
        check.evidence.append("Both rate limiting and input length limits present.")
    elif has_rate or has_length:
        check.status = CheckStatus.PARTIAL
        present = "rate limiting" if has_rate else "input length limits"
        missing = "input length limits" if has_rate else "rate limiting"
        check.evidence.append(f"{present.capitalize()} present, {missing} missing.")
        check.remediation = (
            f"Add {'LengthValidator (max_chars)' if has_rate else 'RateLimitValidator'} "
            "to cover both flood and oversized-input vectors."
        )
    else:
        check.evidence.append("No rate limiting or input length limits found.")
    return check


def _check_llm06(pipeline: GuardrailPipeline) -> OwaspCheck:
    """LLM06 Sensitive Information Disclosure: PII and secrets scanning."""
    check = OwaspCheck(
        check_id="LLM06",
        title="Sensitive Information Disclosure",
        status=CheckStatus.FAIL,
        automated=True,
        remediation=(
            "Add PIIValidator and SecretsValidator (ideally with redaction) "
            "so emails, SSNs, API keys, and credentials never reach the "
            "model or its logs."
        ),
    )
    names = _names(pipeline)
    has_pii = "pii" in names
    has_secrets = "secrets" in names
    has_custom = "regex" in names

    if has_custom:
        check.evidence.append("Custom regex patterns present (domain-specific PII).")

    if has_pii and has_secrets:
        check.status = CheckStatus.PASS
        check.evidence.append("Both PII and secrets scanning present.")
    elif has_pii or has_secrets:
        check.status = CheckStatus.PARTIAL
        present = "PII scanning" if has_pii else "Secrets scanning"
        missing = "secrets scanning" if has_pii else "PII scanning"
        check.evidence.append(f"{present} present, {missing} missing.")
        check.remediation = (
            f"Add {'SecretsValidator' if has_pii else 'PIIValidator'} to cover "
            "both personal data and credential leakage."
        )
    else:
        check.evidence.append("No PII or secrets scanning found.")
    return check


def _manual_check(check_id: str, title: str, remediation: str) -> OwaspCheck:
    return OwaspCheck(
        check_id=check_id,
        title=title,
        status=CheckStatus.MANUAL,
        automated=False,
        evidence=["Architectural or process-level risk; review manually."],
        remediation=remediation,
    )


def audit_pipeline(pipeline: GuardrailPipeline) -> OwaspAudit:
    """Audit a pipeline against the OWASP Top 10 for LLM Applications.

    Automated checks (LLM01, LLM02, LLM04, LLM06) inspect the pipeline's
    validators and actions. The remaining risks cannot be evaluated from
    a text-guardrail pipeline and are returned as manual review items
    with remediation guidance.

    Args:
        pipeline: The configured guardrail pipeline to audit.

    Returns:
        An :class:`OwaspAudit` with all ten checks in LLM01..LLM10 order.
    """
    checks = [
        _check_llm01(pipeline),
        _check_llm02(pipeline),
        _manual_check(
            "LLM03",
            "Training Data Poisoning",
            "Vet fine-tuning and RAG data sources, pin dataset versions, "
            "and audit third-party data for planted content.",
        ),
        _check_llm04(pipeline),
        _manual_check(
            "LLM05",
            "Supply Chain Vulnerabilities",
            "Pin model and package versions, verify checksums of downloaded "
            "weights, and review third-party plugin/tool dependencies.",
        ),
        _check_llm06(pipeline),
        _manual_check(
            "LLM07",
            "Insecure Plugin Design",
            "Give tools/plugins least-privilege scopes, validate their "
            "parameters, and require confirmation for destructive actions.",
        ),
        _manual_check(
            "LLM08",
            "Excessive Agency",
            "Limit which tools the model may call, cap iteration counts, "
            "and keep a human in the loop for irreversible operations.",
        ),
        _manual_check(
            "LLM09",
            "Overreliance",
            "Communicate model limitations to users, add citations or "
            "verification steps, and monitor output quality over time.",
        ),
        _manual_check(
            "LLM10",
            "Model Theft",
            "Restrict and monitor model/API access, rate-limit per client, "
            "and watermark or log outputs to detect extraction attempts.",
        ),
    ]
    return OwaspAudit(checks=checks)
