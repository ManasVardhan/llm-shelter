"""Tests for length validation."""

from __future__ import annotations

import pytest

from llm_shelter.validators.length import LengthValidator


class TestCharLimit:
    def test_within_char_limit(self) -> None:
        v = LengthValidator(max_chars=100)
        result = v.validate("Hello world")
        assert result.is_valid

    def test_exceeds_char_limit(self) -> None:
        v = LengthValidator(max_chars=5)
        result = v.validate("This is too long")
        assert not result.is_valid
        assert any(f.category == "max_chars" for f in result.findings)

    def test_exact_char_limit(self) -> None:
        v = LengthValidator(max_chars=5)
        result = v.validate("Hello")
        assert result.is_valid

    def test_one_over_char_limit(self) -> None:
        v = LengthValidator(max_chars=5)
        result = v.validate("Hello!")
        assert not result.is_valid

    def test_empty_string(self) -> None:
        v = LengthValidator(max_chars=10)
        result = v.validate("")
        assert result.is_valid


class TestTokenLimit:
    def test_within_token_limit(self) -> None:
        v = LengthValidator(max_tokens=100)
        result = v.validate("Hello world")
        assert result.is_valid

    def test_exceeds_token_limit(self) -> None:
        v = LengthValidator(max_tokens=1)
        result = v.validate("This is a really long sentence that will exceed one token")
        assert not result.is_valid
        assert any(f.category == "max_tokens" for f in result.findings)


class TestTokenEstimation:
    def test_estimate_tokens(self) -> None:
        est = LengthValidator.estimate_tokens("Hello world")
        assert est >= 1
        assert isinstance(est, int)

    def test_estimate_empty(self) -> None:
        est = LengthValidator.estimate_tokens("")
        assert est >= 1  # min is 1

    def test_estimate_long_text(self) -> None:
        text = "word " * 100
        est = LengthValidator.estimate_tokens(text)
        assert est > 10  # 500 chars / 4 = 125


class TestCombinedLimits:
    def test_both_limits_pass(self) -> None:
        v = LengthValidator(max_chars=100, max_tokens=100)
        result = v.validate("Short text")
        assert result.is_valid

    def test_chars_fail_tokens_pass(self) -> None:
        v = LengthValidator(max_chars=3, max_tokens=100)
        result = v.validate("Hello")
        assert not result.is_valid

    def test_both_fail(self) -> None:
        v = LengthValidator(max_chars=3, max_tokens=1)
        result = v.validate("This is way too long for both limits")
        assert not result.is_valid
        assert len(result.findings) == 2


class TestNoLimits:
    def test_no_limits_always_passes(self) -> None:
        v = LengthValidator()
        result = v.validate("x" * 10000)
        assert result.is_valid
