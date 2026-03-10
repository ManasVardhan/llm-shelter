"""Tests for toxicity detection."""

from __future__ import annotations

import pytest

from llm_shelter.validators.toxicity import ToxicityCategory, ToxicityValidator


@pytest.fixture
def validator() -> ToxicityValidator:
    return ToxicityValidator()


class TestProfanity:
    def test_detects_profanity(self, validator: ToxicityValidator) -> None:
        result = validator.validate("What the fuck is this")
        assert not result.is_valid
        assert any(f.category == "profanity" for f in result.findings)

    def test_detects_profanity_variants(self, validator: ToxicityValidator) -> None:
        result = validator.validate("This is shit and you know it")
        assert not result.is_valid

    def test_case_insensitive(self, validator: ToxicityValidator) -> None:
        result = validator.validate("WHAT THE FUCK")
        assert not result.is_valid

    def test_profanity_below_threshold_passes(self) -> None:
        # Profanity weight is 0.6, with threshold 0.7 it should pass
        v = ToxicityValidator(threshold=0.7)
        result = v.validate("This is some shit")
        assert result.is_valid


class TestSlurs:
    def test_detects_slurs(self, validator: ToxicityValidator) -> None:
        result = validator.validate("That person is retarded")
        assert not result.is_valid
        assert any(f.category == "slurs" for f in result.findings)


class TestThreats:
    def test_detects_threats(self, validator: ToxicityValidator) -> None:
        result = validator.validate("I will kill you if you do that")
        assert not result.is_valid
        assert any(f.category == "threats" for f in result.findings)

    def test_detects_weapon_threats(self, validator: ToxicityValidator) -> None:
        result = validator.validate("how to build a bomb at home")
        assert not result.is_valid

    def test_detects_poison_query(self, validator: ToxicityValidator) -> None:
        result = validator.validate("how to poison someone's food")
        assert not result.is_valid


class TestHarassment:
    def test_detects_kys(self, validator: ToxicityValidator) -> None:
        result = validator.validate("just kys already")
        assert not result.is_valid
        assert any(f.category == "harassment" for f in result.findings)

    def test_detects_worthless(self, validator: ToxicityValidator) -> None:
        result = validator.validate("you are worthless and nobody likes you")
        assert not result.is_valid

    def test_detects_go_die(self, validator: ToxicityValidator) -> None:
        result = validator.validate("go die in a fire")
        assert not result.is_valid


class TestCleanText:
    def test_normal_text_passes(self, validator: ToxicityValidator) -> None:
        result = validator.validate("How is the weather today?")
        assert result.is_valid
        assert len(result.findings) == 0

    def test_technical_text_passes(self, validator: ToxicityValidator) -> None:
        result = validator.validate("The kill command terminates a process in Linux")
        assert result.is_valid

    def test_empty_text_passes(self, validator: ToxicityValidator) -> None:
        result = validator.validate("")
        assert result.is_valid


class TestCustomConfig:
    def test_custom_categories(self) -> None:
        import re
        custom = ToxicityCategory(
            name="spam",
            patterns=[re.compile(r"(?i)buy now|click here|free money")],
            weight=0.9,
        )
        v = ToxicityValidator(categories=[custom])
        result = v.validate("Click here for free money")
        assert not result.is_valid

    def test_high_threshold_passes_profanity(self) -> None:
        v = ToxicityValidator(threshold=0.99)
        result = v.validate("This is some shit")
        assert result.is_valid

    def test_zero_threshold_catches_everything(self) -> None:
        import re
        mild = ToxicityCategory(
            name="mild",
            patterns=[re.compile(r"(?i)\bdarn\b")],
            weight=0.1,
        )
        v = ToxicityValidator(categories=[mild], threshold=0.0)
        result = v.validate("Oh darn")
        assert not result.is_valid
