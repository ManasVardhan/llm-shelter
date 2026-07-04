"""Tests for secret and credential detection.

All keys and tokens in this file are fake, randomly typed strings that
only mimic the shape of real credentials.
"""

from __future__ import annotations

import re

import pytest
from click.testing import CliRunner

from llm_shelter import SecretsValidator
from llm_shelter.cli import _make_cli
from llm_shelter.pipeline import Action
from llm_shelter.validators.secrets import DEFAULT_SECRET_PATTERNS, SecretPattern

FAKE_OPENAI = "sk-abcdefghijklmnopqrstuvwx1234"
FAKE_OPENAI_PROJ = "sk-proj-abcdefghijklmnopqrstuvwx1234"
FAKE_ANTHROPIC = "sk-ant-api03-abcdefghijklmnopqrst1234"
FAKE_GITHUB_PAT = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_GITHUB_FINE = "github_pat_" + "a1B2c3D4e5F6g7H8i9J0k1"
FAKE_SLACK = "xoxb-1234567890-abcdefghij"
FAKE_GOOGLE = "AIza" + "B" * 35
FAKE_HF = "hf_" + "abcdefghijklmnopqrstuvwxyz1234"
# Built by concatenation so secret scanners do not flag this test fixture
FAKE_STRIPE = "sk_test_" + "abcdefghijklmnopqrst1234"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijklmnop"


@pytest.fixture
def validator() -> SecretsValidator:
    return SecretsValidator(redact=True)


class TestProviderKeys:
    def test_openai_key(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"my key is {FAKE_OPENAI}")
        assert not result.is_valid
        assert any(f.category == "openai_api_key" for f in result.findings)
        assert "[OPENAI_KEY_REDACTED]" in result.text
        assert FAKE_OPENAI not in result.text

    def test_openai_project_key(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"key={FAKE_OPENAI_PROJ}")
        assert not result.is_valid
        assert any(f.category == "openai_api_key" for f in result.findings)

    def test_anthropic_key(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}")
        assert not result.is_valid
        assert any(f.category == "anthropic_api_key" for f in result.findings)
        assert "[ANTHROPIC_KEY_REDACTED]" in result.text

    def test_anthropic_not_double_reported_as_openai(
        self, validator: SecretsValidator
    ) -> None:
        result = validator.validate(f"key: {FAKE_ANTHROPIC}")
        assert len(result.findings) == 1
        assert result.findings[0].category == "anthropic_api_key"

    def test_github_classic_token(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"token: {FAKE_GITHUB_PAT}")
        assert not result.is_valid
        assert any(f.category == "github_token" for f in result.findings)
        assert "[GITHUB_TOKEN_REDACTED]" in result.text

    def test_github_fine_grained_token(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"token: {FAKE_GITHUB_FINE}")
        assert not result.is_valid
        assert any(f.category == "github_token" for f in result.findings)

    def test_slack_token(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"SLACK_TOKEN={FAKE_SLACK}")
        assert not result.is_valid
        assert any(f.category == "slack_token" for f in result.findings)

    def test_google_api_key(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"maps key {FAKE_GOOGLE}")
        assert not result.is_valid
        assert any(f.category == "google_api_key" for f in result.findings)

    def test_huggingface_token(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"HF_TOKEN={FAKE_HF}")
        assert not result.is_valid
        assert any(f.category == "huggingface_token" for f in result.findings)

    def test_stripe_key(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"stripe: {FAKE_STRIPE}")
        assert not result.is_valid
        assert any(f.category == "stripe_key" for f in result.findings)


class TestGenericSecrets:
    def test_jwt(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"Authorization uses {FAKE_JWT}")
        assert not result.is_valid
        assert any(f.category == "jwt" for f in result.findings)
        assert "[JWT_REDACTED]" in result.text

    def test_private_key_header(self, validator: SecretsValidator) -> None:
        result = validator.validate("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert not result.is_valid
        assert any(f.category == "private_key" for f in result.findings)

    def test_openssh_private_key_header(self, validator: SecretsValidator) -> None:
        result = validator.validate("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert not result.is_valid

    def test_bearer_token(self, validator: SecretsValidator) -> None:
        result = validator.validate("Authorization: Bearer abcdefghijklmnopqrstuv123")
        assert not result.is_valid
        assert any(f.category == "bearer_token" for f in result.findings)

    def test_bearer_token_case_insensitive(self, validator: SecretsValidator) -> None:
        result = validator.validate("authorization: bearer abcdefghijklmnopqrstuv123")
        assert not result.is_valid


class TestCleanText:
    def test_plain_text_passes(self, validator: SecretsValidator) -> None:
        result = validator.validate("Nothing sensitive here, just words.")
        assert result.is_valid
        assert result.findings == []
        assert result.text == result.original_text
        assert result.action_taken == Action.PASSTHROUGH

    def test_short_sk_prefix_not_matched(self, validator: SecretsValidator) -> None:
        result = validator.validate("the sk-1 variant of the model")
        assert result.is_valid

    def test_bearer_word_alone_not_matched(self, validator: SecretsValidator) -> None:
        result = validator.validate("The bearer of this message is trusted.")
        assert result.is_valid


class TestRedactionBehavior:
    def test_redact_false_keeps_text(self) -> None:
        validator = SecretsValidator(redact=False)
        result = validator.validate(f"key {FAKE_OPENAI}")
        assert not result.is_valid
        assert result.text == result.original_text
        assert FAKE_OPENAI in result.text

    def test_multiple_secrets_all_redacted(self, validator: SecretsValidator) -> None:
        text = f"a={FAKE_OPENAI} b={FAKE_GITHUB_PAT} c={FAKE_SLACK}"
        result = validator.validate(text)
        assert len(result.findings) == 3
        assert FAKE_OPENAI not in result.text
        assert FAKE_GITHUB_PAT not in result.text
        assert FAKE_SLACK not in result.text
        assert "[OPENAI_KEY_REDACTED]" in result.text
        assert "[GITHUB_TOKEN_REDACTED]" in result.text
        assert "[SLACK_TOKEN_REDACTED]" in result.text

    def test_surrounding_text_preserved(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"before {FAKE_HF} after")
        assert result.text == "before [HF_TOKEN_REDACTED] after"

    def test_description_truncates_secret(self, validator: SecretsValidator) -> None:
        result = validator.validate(FAKE_OPENAI)
        desc = result.findings[0].description
        assert FAKE_OPENAI not in desc
        assert "***" in desc

    def test_action_taken_reported(self, validator: SecretsValidator) -> None:
        result = validator.validate(FAKE_OPENAI)
        assert result.action_taken == Action.REDACT

    def test_custom_action(self) -> None:
        validator = SecretsValidator(action=Action.BLOCK)
        result = validator.validate(FAKE_OPENAI)
        assert result.action_taken == Action.BLOCK


class TestCustomPatterns:
    def test_custom_pattern_only(self) -> None:
        custom = SecretPattern(
            name="acme_key",
            pattern=re.compile(r"\bacme_[0-9]{8}\b"),
            placeholder="[ACME_REDACTED]",
        )
        validator = SecretsValidator(patterns=[custom])
        result = validator.validate(f"acme_12345678 and {FAKE_OPENAI}")
        assert len(result.findings) == 1
        assert result.findings[0].category == "acme_key"
        assert "[ACME_REDACTED]" in result.text
        assert FAKE_OPENAI in result.text

    def test_default_patterns_not_mutated(self) -> None:
        validator = SecretsValidator()
        validator.patterns.append(
            SecretPattern("x", re.compile("x"), "[X]")
        )
        assert all(p.name != "x" for p in DEFAULT_SECRET_PATTERNS)

    def test_severity_propagates(self, validator: SecretsValidator) -> None:
        result = validator.validate(f"token {FAKE_JWT}")
        jwt_findings = [f for f in result.findings if f.category == "jwt"]
        assert jwt_findings[0].severity == 0.9


class TestSecretsCLI:
    def test_scan_detects_secret(self) -> None:
        runner = CliRunner()
        result = runner.invoke(_make_cli(), ["scan", f"key is {FAKE_OPENAI}"])
        assert result.exit_code == 0
        assert "secrets/openai_api_key" in result.output

    def test_scan_no_secrets_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            _make_cli(), ["scan", "--no-secrets", f"key is {FAKE_OPENAI}"]
        )
        assert "secrets/" not in result.output

    def test_scan_redact_shows_placeholder(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            _make_cli(), ["scan", "--redact", f"key is {FAKE_GITHUB_PAT}"]
        )
        assert result.exit_code == 0
        assert "[GITHUB_TOKEN_REDACTED]" in result.output
        assert FAKE_GITHUB_PAT not in result.output

    def test_report_includes_secrets(self) -> None:
        import json

        runner = CliRunner()
        result = runner.invoke(_make_cli(), ["report", f"key {FAKE_SLACK}"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        # Secrets run at WARN level in report mode, so is_valid stays True
        # but the finding must be present.
        assert payload["findings_count"] >= 1
        assert any(f["validator"] == "secrets" for f in payload["findings"])

    def test_batch_flags_secret_file(self, tmp_path) -> None:
        secret_file = tmp_path / "creds.txt"
        secret_file.write_text(f"token: {FAKE_HF}\n")
        clean_file = tmp_path / "clean.txt"
        clean_file.write_text("nothing here\n")
        runner = CliRunner()
        result = runner.invoke(
            _make_cli(), ["batch", str(secret_file), str(clean_file)]
        )
        assert result.exit_code == 0
        assert "secrets/huggingface_token" in result.output
        assert "clean.txt: OK" in result.output
