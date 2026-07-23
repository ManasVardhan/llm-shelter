"""Tests for the OWASP LLM Top 10 audit module and the audit CLI command."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from llm_shelter import (
    GuardrailPipeline,
    InjectionValidator,
    LengthValidator,
    PIIValidator,
    RateLimitValidator,
    RegexValidator,
    RuleValidator,
    SchemaValidator,
    SecretsValidator,
    ToxicityValidator,
    audit_pipeline,
)
from llm_shelter.cli import _make_cli
from llm_shelter.owasp import CheckStatus, OwaspAudit, OwaspCheck
from llm_shelter.pipeline import Action
from llm_shelter.validators.rules import Rule


def _check(audit: OwaspAudit, check_id: str) -> OwaspCheck:
    return next(c for c in audit.checks if c.check_id == check_id)


def _full_pipeline() -> GuardrailPipeline:
    pipeline = GuardrailPipeline()
    pipeline.add(PIIValidator(redact=True), Action.REDACT)
    pipeline.add(SecretsValidator(redact=True), Action.REDACT)
    pipeline.add(InjectionValidator(), Action.BLOCK)
    pipeline.add(ToxicityValidator(), Action.BLOCK)
    pipeline.add(SchemaValidator(schema={"type": "object"}), Action.WARN)
    pipeline.add(LengthValidator(max_chars=4000), Action.BLOCK)
    pipeline.add(RateLimitValidator(max_requests=60, window_seconds=60), Action.BLOCK)
    return pipeline


class TestPipelineValidatorsProperty:
    def test_returns_pairs_in_order(self):
        pipeline = GuardrailPipeline()
        pii = PIIValidator()
        injection = InjectionValidator()
        pipeline.add(pii, Action.WARN)
        pipeline.add(injection, Action.BLOCK)
        assert pipeline.validators == [(pii, Action.WARN), (injection, Action.BLOCK)]

    def test_returns_copy(self):
        pipeline = GuardrailPipeline()
        pipeline.add(PIIValidator(), Action.WARN)
        pipeline.validators.clear()
        assert len(pipeline.validators) == 1


class TestAuditStructure:
    def test_ten_checks_in_order(self):
        audit = audit_pipeline(GuardrailPipeline())
        assert [c.check_id for c in audit.checks] == [f"LLM{i:02d}" for i in range(1, 11)]

    def test_automated_and_manual_split(self):
        audit = audit_pipeline(GuardrailPipeline())
        automated = {c.check_id for c in audit.checks if c.automated}
        assert automated == {"LLM01", "LLM02", "LLM04", "LLM06"}
        assert len(audit.manual) == 6

    def test_manual_checks_have_remediation(self):
        audit = audit_pipeline(GuardrailPipeline())
        for check in audit.manual:
            assert check.remediation
            assert check.status == CheckStatus.MANUAL

    def test_empty_pipeline_fails_all_automated(self):
        audit = audit_pipeline(GuardrailPipeline())
        assert len(audit.failed) == 4
        assert audit.has_gaps

    def test_full_pipeline_passes_all_automated(self):
        audit = audit_pipeline(_full_pipeline())
        assert len(audit.failed) == 0
        assert len(audit.partial) == 0
        assert len(audit.passed) == 4
        assert not audit.has_gaps

    def test_summary_string(self):
        audit = audit_pipeline(_full_pipeline())
        assert audit.summary() == "4 pass, 0 partial, 0 fail, 6 manual review"


class TestLLM01PromptInjection:
    def test_blocking_injection_passes(self):
        pipeline = GuardrailPipeline().add(InjectionValidator(), Action.BLOCK)
        assert _check(audit_pipeline(pipeline), "LLM01").status == CheckStatus.PASS

    def test_warn_only_injection_is_partial(self):
        pipeline = GuardrailPipeline().add(InjectionValidator(), Action.WARN)
        check = _check(audit_pipeline(pipeline), "LLM01")
        assert check.status == CheckStatus.PARTIAL
        assert "Action.BLOCK" in check.remediation

    def test_missing_injection_fails(self):
        check = _check(audit_pipeline(GuardrailPipeline()), "LLM01")
        assert check.status == CheckStatus.FAIL
        assert "InjectionValidator" in check.remediation


class TestLLM02OutputHandling:
    def test_schema_validator_passes(self):
        pipeline = GuardrailPipeline().add(SchemaValidator(schema={"type": "object"}), Action.WARN)
        assert _check(audit_pipeline(pipeline), "LLM02").status == CheckStatus.PASS

    def test_toxicity_only_is_partial(self):
        pipeline = GuardrailPipeline().add(ToxicityValidator(), Action.BLOCK)
        check = _check(audit_pipeline(pipeline), "LLM02")
        assert check.status == CheckStatus.PARTIAL
        assert "SchemaValidator" in check.remediation

    def test_rules_only_is_partial(self):
        pipeline = GuardrailPipeline().add(
            RuleValidator(rules=[Rule(name="no_x", check=lambda t: "x" not in t)]),
            Action.WARN,
        )
        assert _check(audit_pipeline(pipeline), "LLM02").status == CheckStatus.PARTIAL

    def test_missing_output_validation_fails(self):
        assert _check(audit_pipeline(GuardrailPipeline()), "LLM02").status == CheckStatus.FAIL


class TestLLM04DenialOfService:
    def test_rate_and_length_pass(self):
        pipeline = GuardrailPipeline()
        pipeline.add(RateLimitValidator(), Action.BLOCK)
        pipeline.add(LengthValidator(max_chars=1000), Action.BLOCK)
        assert _check(audit_pipeline(pipeline), "LLM04").status == CheckStatus.PASS

    def test_rate_only_is_partial(self):
        pipeline = GuardrailPipeline().add(RateLimitValidator(), Action.BLOCK)
        check = _check(audit_pipeline(pipeline), "LLM04")
        assert check.status == CheckStatus.PARTIAL
        assert "LengthValidator" in check.remediation

    def test_length_only_is_partial(self):
        pipeline = GuardrailPipeline().add(LengthValidator(max_chars=1000), Action.BLOCK)
        check = _check(audit_pipeline(pipeline), "LLM04")
        assert check.status == CheckStatus.PARTIAL
        assert "RateLimitValidator" in check.remediation

    def test_neither_fails(self):
        assert _check(audit_pipeline(GuardrailPipeline()), "LLM04").status == CheckStatus.FAIL


class TestLLM06SensitiveInformation:
    def test_pii_and_secrets_pass(self):
        pipeline = GuardrailPipeline()
        pipeline.add(PIIValidator(), Action.WARN)
        pipeline.add(SecretsValidator(), Action.WARN)
        assert _check(audit_pipeline(pipeline), "LLM06").status == CheckStatus.PASS

    def test_pii_only_is_partial(self):
        pipeline = GuardrailPipeline().add(PIIValidator(), Action.WARN)
        check = _check(audit_pipeline(pipeline), "LLM06")
        assert check.status == CheckStatus.PARTIAL
        assert "SecretsValidator" in check.remediation

    def test_secrets_only_is_partial(self):
        pipeline = GuardrailPipeline().add(SecretsValidator(), Action.WARN)
        check = _check(audit_pipeline(pipeline), "LLM06")
        assert check.status == CheckStatus.PARTIAL
        assert "PIIValidator" in check.remediation

    def test_custom_regex_noted_in_evidence(self):
        pipeline = GuardrailPipeline()
        pipeline.add(RegexValidator.from_specs(["emp=EMP-\\d+"]), Action.WARN)
        check = _check(audit_pipeline(pipeline), "LLM06")
        assert check.status == CheckStatus.FAIL
        assert any("Custom regex" in note for note in check.evidence)

    def test_neither_fails(self):
        assert _check(audit_pipeline(GuardrailPipeline()), "LLM06").status == CheckStatus.FAIL


class TestAuditCLI:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def cli(self):
        return _make_cli()

    def test_default_flags_render_checklist(self, runner, cli):
        result = runner.invoke(cli, ["audit"])
        assert result.exit_code == 0, result.output
        for i in range(1, 11):
            assert f"LLM{i:02d}" in result.output
        assert "Summary:" in result.output

    def test_default_flags_pass_injection_and_sensitive(self, runner, cli):
        result = runner.invoke(cli, ["audit"])
        assert "[PASS] LLM01" in result.output
        assert "[PASS] LLM06" in result.output
        # No rate limit or max chars by default, so DoS fails.
        assert "[FAIL] LLM04" in result.output

    def test_remediation_shown_for_gaps(self, runner, cli):
        result = runner.invoke(cli, ["audit"])
        assert "Fix:" in result.output

    def test_full_coverage_flags(self, runner, cli):
        result = runner.invoke(
            cli, ["audit", "--max-chars", "4000", "--rate-limit", "60"]
        )
        assert result.exit_code == 0, result.output
        assert "[PASS] LLM04" in result.output
        assert "[FAIL]" not in result.output

    def test_disabling_validators_creates_gaps(self, runner, cli):
        result = runner.invoke(cli, ["audit", "--no-injection", "--no-pii", "--no-secrets"])
        assert "[FAIL] LLM01" in result.output
        assert "[FAIL] LLM06" in result.output

    def test_json_output_parses(self, runner, cli):
        result = runner.invoke(cli, ["audit", "--json-output"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert len(payload["checks"]) == 10
        assert payload["summary"]["manual"] == 6
        assert payload["summary"]["has_gaps"] is True

    def test_json_check_fields(self, runner, cli):
        result = runner.invoke(cli, ["audit", "--json-output"])
        payload = json.loads(result.output)
        first = payload["checks"][0]
        assert first["id"] == "LLM01"
        assert first["title"] == "Prompt Injection"
        assert first["status"] == "pass"
        assert first["automated"] is True

    def test_fail_on_gaps_exits_1(self, runner, cli):
        result = runner.invoke(cli, ["audit", "--fail-on-gaps"])
        assert result.exit_code == 1

    def test_fail_on_gaps_passes_with_full_coverage(self, runner, cli):
        result = runner.invoke(
            cli,
            ["audit", "--fail-on-gaps", "--max-chars", "4000", "--rate-limit", "60"],
        )
        assert result.exit_code == 0, result.output

    def test_partial_does_not_trip_fail_on_gaps(self, runner, cli):
        # max-chars alone makes LLM04 partial (no rate limit) and default
        # toxicity makes LLM02 partial. Partial is not a hard gap, so
        # --fail-on-gaps must still exit 0.
        json_result = runner.invoke(cli, ["audit", "--max-chars", "4000", "--json-output"])
        payload = json.loads(json_result.output)
        assert payload["summary"]["fail"] == 0
        assert payload["summary"]["partial"] >= 1

        result = runner.invoke(cli, ["audit", "--fail-on-gaps", "--max-chars", "4000"])
        assert result.exit_code == 0, result.output

    def test_invalid_rate_limit_rejected(self, runner, cli):
        result = runner.invoke(cli, ["audit", "--rate-limit", "0"])
        assert result.exit_code == 1
        assert "positive" in result.output

    def test_custom_pattern_flows_into_audit(self, runner, cli):
        result = runner.invoke(
            cli, ["audit", "-p", "emp=EMP-\\d+", "--json-output"]
        )
        payload = json.loads(result.output)
        llm06 = next(c for c in payload["checks"] if c["id"] == "LLM06")
        assert any("Custom regex" in note for note in llm06["evidence"])

    def test_invalid_pattern_spec_errors(self, runner, cli):
        result = runner.invoke(cli, ["audit", "-p", "not-a-valid-spec"])
        assert result.exit_code == 1


class TestPublicAPI:
    def test_exports(self):
        import llm_shelter

        assert llm_shelter.audit_pipeline is audit_pipeline
        assert llm_shelter.OwaspAudit is OwaspAudit
        assert llm_shelter.OwaspCheck is OwaspCheck
        assert llm_shelter.CheckStatus is CheckStatus
