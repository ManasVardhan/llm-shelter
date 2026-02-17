"""Tests for PII detection and redaction."""

import pytest

from llm_shelter.validators.pii import PIIValidator


@pytest.fixture
def validator() -> PIIValidator:
    return PIIValidator(redact=True)


class TestEmailDetection:
    def test_simple_email(self, validator: PIIValidator) -> None:
        result = validator.validate("Contact me at john@example.com please")
        assert not result.is_valid
        assert any(f.category == "email" for f in result.findings)
        assert "[EMAIL_REDACTED]" in result.text
        assert "john@example.com" not in result.text

    def test_email_with_plus(self, validator: PIIValidator) -> None:
        result = validator.validate("Send to user+tag@gmail.com")
        assert not result.is_valid
        assert "[EMAIL_REDACTED]" in result.text

    def test_no_email(self, validator: PIIValidator) -> None:
        result = validator.validate("This has no email addresses")
        assert result.is_valid


class TestPhoneDetection:
    def test_us_phone_dashes(self, validator: PIIValidator) -> None:
        result = validator.validate("Call me at 555-123-4567")
        assert not result.is_valid
        assert any(f.category == "phone" for f in result.findings)

    def test_us_phone_parens(self, validator: PIIValidator) -> None:
        result = validator.validate("Phone: (555) 123-4567")
        assert not result.is_valid

    def test_us_phone_with_country(self, validator: PIIValidator) -> None:
        result = validator.validate("Call +1 555-123-4567")
        assert not result.is_valid


class TestSSNDetection:
    def test_ssn_dashes(self, validator: PIIValidator) -> None:
        result = validator.validate("My SSN is 123-45-6789")
        assert not result.is_valid
        assert any(f.category == "ssn" for f in result.findings)

    def test_ssn_no_dashes_no_match(self, validator: PIIValidator) -> None:
        """Bare 9-digit numbers should NOT trigger SSN detection (false positive fix)."""
        result = validator.validate("SSN: 123456789")
        assert result.is_valid

    def test_ssn_with_spaces(self, validator: PIIValidator) -> None:
        result = validator.validate("My SSN is 123 45 6789")
        assert not result.is_valid
        assert any(f.category == "ssn" for f in result.findings)


class TestCreditCardDetection:
    def test_visa(self, validator: PIIValidator) -> None:
        result = validator.validate("Card: 4111-1111-1111-1111")
        assert not result.is_valid
        assert any(f.category == "credit_card" for f in result.findings)

    def test_mastercard(self, validator: PIIValidator) -> None:
        result = validator.validate("MC: 5500 0000 0000 0004")
        assert not result.is_valid

    def test_amex(self, validator: PIIValidator) -> None:
        result = validator.validate("Amex: 3782-8224-6310-005")
        assert not result.is_valid


class TestMultiplePII:
    def test_redact_multiple(self, validator: PIIValidator) -> None:
        text = "Email: test@test.com, Phone: 555-123-4567"
        result = validator.validate(text)
        assert not result.is_valid
        assert len(result.findings) >= 2
        assert "[EMAIL_REDACTED]" in result.text
        assert "[PHONE_REDACTED]" in result.text
