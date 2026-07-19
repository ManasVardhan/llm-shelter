"""Tests for the custom regex pattern validator.

Covers RegexPattern construction, spec parsing, RegexValidator
detection and redaction, pipeline integration, and the CLI ``-p``
option on scan, batch, and report.
"""

from __future__ import annotations

import json
import re

import pytest
from click.testing import CliRunner

from llm_shelter import GuardrailPipeline, RegexPattern, RegexValidator
from llm_shelter.cli import _make_cli
from llm_shelter.pipeline import Action
from llm_shelter.validators.regex import compile_pattern, parse_pattern_spec


def _cli():
    """Return the real CLI group for CliRunner tests."""
    return _make_cli()


# ---------------------------------------------------------------------------
# RegexPattern
# ---------------------------------------------------------------------------

class TestRegexPattern:
    """RegexPattern dataclass construction and defaults."""

    def test_placeholder_derived_from_name(self) -> None:
        p = RegexPattern(name="employee_id", pattern=re.compile(r"EMP-\d+"))
        assert p.placeholder == "[EMPLOYEE_ID_REDACTED]"

    def test_placeholder_sanitizes_special_chars(self) -> None:
        p = RegexPattern(name="my ticket!id", pattern=re.compile(r"x"))
        assert p.placeholder == "[MY_TICKET_ID_REDACTED]"

    def test_custom_placeholder_preserved(self) -> None:
        p = RegexPattern(name="a", pattern=re.compile(r"x"), placeholder="[HIDDEN]")
        assert p.placeholder == "[HIDDEN]"

    def test_name_is_stripped(self) -> None:
        p = RegexPattern(name="  ticket  ", pattern=re.compile(r"x"))
        assert p.name == "ticket"

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            RegexPattern(name="", pattern=re.compile(r"x"))

    def test_whitespace_name_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            RegexPattern(name="   ", pattern=re.compile(r"x"))

    def test_severity_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="severity"):
            RegexPattern(name="a", pattern=re.compile(r"x"), severity=1.5)

    def test_negative_severity_raises(self) -> None:
        with pytest.raises(ValueError, match="severity"):
            RegexPattern(name="a", pattern=re.compile(r"x"), severity=-0.1)

    def test_all_symbol_name_gets_custom_placeholder(self) -> None:
        p = RegexPattern(name="!!!", pattern=re.compile(r"x"))
        assert p.placeholder == "[CUSTOM_REDACTED]"


# ---------------------------------------------------------------------------
# compile_pattern / parse_pattern_spec
# ---------------------------------------------------------------------------

class TestCompileAndParse:
    """Helpers that build RegexPattern from strings."""

    def test_compile_valid(self) -> None:
        p = compile_pattern("ticket", r"JIRA-\d+")
        assert p.pattern.search("see JIRA-42")

    def test_compile_invalid_regex_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid regex for pattern 'bad'"):
            compile_pattern("bad", r"[unclosed")

    def test_compile_with_flags(self) -> None:
        p = compile_pattern("codename", r"phoenix", flags=re.IGNORECASE)
        assert p.pattern.search("Project PHOENIX launch")

    def test_parse_valid_spec(self) -> None:
        p = parse_pattern_spec(r"employee_id=EMP-\d{5}")
        assert p.name == "employee_id"
        assert p.pattern.search("EMP-12345")

    def test_parse_spec_regex_may_contain_equals(self) -> None:
        p = parse_pattern_spec(r"param=id=\d+")
        assert p.name == "param"
        assert p.pattern.search("id=99")

    def test_parse_spec_missing_equals_raises(self) -> None:
        with pytest.raises(ValueError, match="expected LABEL=REGEX"):
            parse_pattern_spec("noequals")

    def test_parse_spec_empty_label_raises(self) -> None:
        with pytest.raises(ValueError, match="label is empty"):
            parse_pattern_spec(r"=\d+")

    def test_parse_spec_empty_regex_raises(self) -> None:
        with pytest.raises(ValueError, match="regex is empty"):
            parse_pattern_spec("label=")

    def test_parse_spec_bad_regex_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid regex"):
            parse_pattern_spec("bad=[oops")


# ---------------------------------------------------------------------------
# RegexValidator
# ---------------------------------------------------------------------------

class TestRegexValidator:
    """Detection, redaction, and edge cases."""

    def test_empty_patterns_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one pattern"):
            RegexValidator([])

    def test_from_specs_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            RegexValidator.from_specs([])

    def test_detects_match_with_finding_fields(self) -> None:
        v = RegexValidator.from_specs([r"employee_id=EMP-\d{5}"])
        result = v.validate("Ask EMP-12345 for access")
        assert not result.is_valid
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.validator == "regex"
        assert f.category == "employee_id"
        assert f.span == (4, 13)
        assert f.severity == 0.8
        assert "EMP-" in f.description
        assert f.redacted_value == "[EMPLOYEE_ID_REDACTED]"

    def test_redacts_match(self) -> None:
        v = RegexValidator.from_specs([r"ticket=JIRA-\d+"])
        result = v.validate("Fixed in JIRA-101 yesterday")
        assert result.text == "Fixed in [TICKET_REDACTED] yesterday"
        assert result.original_text == "Fixed in JIRA-101 yesterday"

    def test_redact_disabled_keeps_text(self) -> None:
        v = RegexValidator.from_specs([r"ticket=JIRA-\d+"], redact=False)
        result = v.validate("Fixed in JIRA-101")
        assert result.text == "Fixed in JIRA-101"
        assert result.has_findings

    def test_multiple_matches_redacted_right_to_left(self) -> None:
        v = RegexValidator.from_specs([r"id=EMP-\d+"])
        result = v.validate("EMP-1 met EMP-22 and EMP-333")
        assert result.text == "[ID_REDACTED] met [ID_REDACTED] and [ID_REDACTED]"
        assert len(result.findings) == 3

    def test_multiple_patterns(self) -> None:
        v = RegexValidator.from_specs([r"emp=EMP-\d+", r"ticket=JIRA-\d+"])
        result = v.validate("EMP-9 fixed JIRA-7")
        categories = {f.category for f in result.findings}
        assert categories == {"emp", "ticket"}

    def test_clean_text_passes(self) -> None:
        v = RegexValidator.from_specs([r"emp=EMP-\d+"])
        result = v.validate("nothing sensitive here")
        assert result.is_valid
        assert result.action_taken == Action.PASSTHROUGH
        assert result.text == "nothing sensitive here"

    def test_zero_width_matches_skipped(self) -> None:
        v = RegexValidator([RegexPattern(name="star", pattern=re.compile(r"z*"))])
        result = v.validate("aaa")
        assert result.is_valid
        assert result.findings == []

    def test_description_truncates_snippet(self) -> None:
        v = RegexValidator.from_specs([r"long=SECRETVALUE\d+"])
        result = v.validate("SECRETVALUE12345")
        assert "SECR***" in result.findings[0].description
        assert "SECRETVALUE12345" not in result.findings[0].description

    def test_custom_action_reported(self) -> None:
        v = RegexValidator.from_specs([r"emp=EMP-\d+"], action=Action.WARN)
        result = v.validate("EMP-1")
        assert result.action_taken == Action.WARN


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

class TestPipelineIntegration:
    """RegexValidator inside a GuardrailPipeline."""

    def test_redact_action_flows_redacted_text(self) -> None:
        pipeline = GuardrailPipeline()
        pipeline.add(RegexValidator.from_specs([r"emp=EMP-\d+"]), Action.REDACT)
        result = pipeline.run("hello EMP-42")
        assert result.text == "hello [EMP_REDACTED]"
        assert result.is_valid is False or result.action_taken == Action.REDACT

    def test_block_action_short_circuits(self) -> None:
        pipeline = GuardrailPipeline()
        pipeline.add(RegexValidator.from_specs([r"codename=phoenix"]), Action.BLOCK)
        result = pipeline.run("project phoenix is secret")
        assert result.blocked
        assert result.text == "project phoenix is secret"

    def test_warn_action_keeps_valid(self) -> None:
        pipeline = GuardrailPipeline()
        pipeline.add(
            RegexValidator.from_specs([r"emp=EMP-\d+"], redact=False), Action.WARN
        )
        result = pipeline.run("hello EMP-42")
        assert result.is_valid
        assert result.has_findings


# ---------------------------------------------------------------------------
# CLI -p option
# ---------------------------------------------------------------------------

class TestCLIPatterns:
    """The -p/--pattern option on scan, batch, and report."""

    def test_scan_detects_custom_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            _cli(), ["scan", "-p", r"employee_id=EMP-\d{5}", "Ask EMP-12345"]
        )
        assert result.exit_code == 0
        assert "regex/employee_id" in result.output

    def test_scan_redacts_custom_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            _cli(),
            ["scan", "--redact", "-p", r"ticket=JIRA-\d+", "Fixed in JIRA-101"],
        )
        assert result.exit_code == 0
        assert "[TICKET_REDACTED]" in result.output

    def test_scan_multiple_patterns(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            _cli(),
            ["scan", "-p", r"emp=EMP-\d+", "-p", r"ticket=JIRA-\d+", "EMP-1 JIRA-2"],
        )
        assert result.exit_code == 0
        assert "regex/emp" in result.output
        assert "regex/ticket" in result.output

    def test_scan_invalid_spec_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(_cli(), ["scan", "-p", "nolabel", "hello"])
        assert result.exit_code == 1
        assert "expected LABEL=REGEX" in result.output

    def test_scan_invalid_regex_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(_cli(), ["scan", "-p", "bad=[oops", "hello"])
        assert result.exit_code == 1
        assert "Invalid regex" in result.output

    def test_scan_without_patterns_unchanged(self) -> None:
        runner = CliRunner()
        result = runner.invoke(_cli(), ["scan", "totally clean text"])
        assert result.exit_code == 0
        assert "No issues found" in result.output

    def test_report_includes_custom_findings(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            _cli(), ["report", "-p", r"emp=EMP-\d+", "hello EMP-42"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        validators = {f["validator"] for f in payload["findings"]}
        assert "regex" in validators
        assert payload["is_valid"] is True  # custom patterns run at WARN in report

    def test_batch_flags_matching_file(self, tmp_path) -> None:
        good = tmp_path / "clean.txt"
        good.write_text("nothing here")
        bad = tmp_path / "flagged.txt"
        bad.write_text("employee EMP-77 did it")
        runner = CliRunner()
        result = runner.invoke(
            _cli(), ["batch", "-p", r"emp=EMP-\d+", str(good), str(bad)]
        )
        assert result.exit_code == 0
        assert "clean.txt: OK" in result.output
        assert "regex/emp" in result.output
