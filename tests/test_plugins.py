"""Tests for entry-point based validator plugins."""

from __future__ import annotations

import json
from typing import Any

import pytest

from llm_shelter import plugins as plugins_mod
from llm_shelter.pipeline import Action, Finding, ValidationResult
from llm_shelter.plugins import (
    PluginError,
    PluginInfo,
    create_validator,
    discover_plugins,
    get_plugin,
    plugin_load_errors,
    register_validator,
    unregister_validator,
)
from llm_shelter.policy import build_pipeline


class BannedWordValidator:
    """Toy plugin validator: flags a configurable banned word."""

    default_action = Action.WARN

    def __init__(self, word: str = "banana") -> None:
        self.name = "banned_word"
        self.word = word

    def validate(self, text: str) -> ValidationResult:
        findings = []
        if self.word in text:
            findings.append(
                Finding(
                    validator=self.name,
                    category="banned_word",
                    description=f"Found banned word {self.word!r}",
                )
            )
        return ValidationResult(
            is_valid=not findings,
            text=text,
            original_text=text,
            findings=findings,
        )


class NotAValidator:
    """Lacks name and validate, so it must be rejected."""


@pytest.fixture(autouse=True)
def clean_registry():
    plugins_mod._registered.clear()
    plugins_mod._entry_point_cache = None
    plugins_mod._entry_point_errors.clear()
    yield
    plugins_mod._registered.clear()
    plugins_mod._entry_point_cache = None
    plugins_mod._entry_point_errors.clear()


class FakeEntryPoint:
    def __init__(self, name: str, obj: Any, value: str = "fake.module:Obj") -> None:
        self.name = name
        self.value = value
        self._obj = obj

    def load(self) -> Any:
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


@pytest.fixture()
def fake_entry_points(monkeypatch: pytest.MonkeyPatch):
    eps: list[FakeEntryPoint] = []

    def entry_points(group: str = "") -> list[FakeEntryPoint]:
        assert group == plugins_mod.PLUGIN_GROUP
        return eps

    monkeypatch.setattr(plugins_mod.metadata, "entry_points", entry_points)
    return eps


class TestRegisterValidator:
    def test_register_and_create(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        validator = create_validator("banned_word", {"word": "kiwi"})
        assert validator.word == "kiwi"
        result = validator.validate("I like kiwi")
        assert result.findings

    def test_register_uses_factory_default_action(self) -> None:
        info = register_validator("banned_word", BannedWordValidator)
        assert info.default_action == Action.WARN

    def test_register_explicit_default_action(self) -> None:
        info = register_validator(
            "banned_word", BannedWordValidator, default_action="block"
        )
        assert info.default_action == Action.BLOCK

    def test_register_invalid_default_action(self) -> None:
        with pytest.raises(PluginError, match="Invalid default_action"):
            register_validator("banned_word", BannedWordValidator, default_action="nope")

    def test_register_passthrough_rejected(self) -> None:
        with pytest.raises(PluginError, match="passthrough"):
            register_validator(
                "banned_word", BannedWordValidator, default_action="passthrough"
            )

    def test_register_empty_name_rejected(self) -> None:
        with pytest.raises(PluginError, match="non-empty"):
            register_validator("  ", BannedWordValidator)

    def test_register_builtin_shadow_rejected(self) -> None:
        with pytest.raises(PluginError, match="shadows a built-in"):
            register_validator("pii", BannedWordValidator)

    def test_register_duplicate_rejected(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        with pytest.raises(PluginError, match="already registered"):
            register_validator("banned_word", BannedWordValidator)

    def test_register_replace(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        info = register_validator(
            "banned_word", BannedWordValidator, default_action="redact", replace=True
        )
        assert info.default_action == Action.REDACT

    def test_unregister(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        unregister_validator("banned_word")
        assert get_plugin("banned_word") is None

    def test_unregister_unknown_raises(self) -> None:
        with pytest.raises(PluginError, match="not registered"):
            unregister_validator("banned_word")


class TestCreateValidator:
    def test_unknown_plugin_raises(self) -> None:
        with pytest.raises(PluginError, match="No plugin validator named"):
            create_validator("nope")

    def test_factory_error_wrapped(self) -> None:
        def broken(**kwargs: Any) -> Any:
            raise RuntimeError("boom")

        register_validator("broken", broken)
        with pytest.raises(PluginError, match="failed to construct: boom"):
            create_validator("broken")

    def test_bad_kwargs_wrapped(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        with pytest.raises(PluginError, match="failed to construct"):
            create_validator("banned_word", {"nonsense": 1})

    def test_non_validator_rejected(self) -> None:
        register_validator("bad", NotAValidator)
        with pytest.raises(PluginError, match="does not satisfy the Validator protocol"):
            create_validator("bad")


class TestEntryPointDiscovery:
    def test_discover_from_entry_points(self, fake_entry_points: list) -> None:
        fake_entry_points.append(
            FakeEntryPoint("banned_word", BannedWordValidator, "my_pkg:BannedWordValidator")
        )
        plugins = discover_plugins()
        assert "banned_word" in plugins
        info = plugins["banned_word"]
        assert info.source == "my_pkg:BannedWordValidator"
        assert info.default_action == Action.WARN

    def test_entry_point_load_failure_recorded(self, fake_entry_points: list) -> None:
        fake_entry_points.append(FakeEntryPoint("broken", ImportError("no module")))
        assert "broken" not in discover_plugins()
        errors = plugin_load_errors()
        assert "broken" in errors
        assert "failed to load" in errors["broken"]

    def test_entry_point_shadowing_builtin_ignored(self, fake_entry_points: list) -> None:
        fake_entry_points.append(FakeEntryPoint("pii", BannedWordValidator))
        assert "pii" not in discover_plugins()
        assert "shadows a built-in" in plugin_load_errors()["pii"]

    def test_registered_takes_precedence(self, fake_entry_points: list) -> None:
        fake_entry_points.append(FakeEntryPoint("banned_word", BannedWordValidator))
        register_validator(
            "banned_word", BannedWordValidator, default_action="redact", replace=True
        )
        assert discover_plugins()["banned_word"].default_action == Action.REDACT

    def test_cache_and_refresh(self, fake_entry_points: list) -> None:
        assert discover_plugins() == {}
        fake_entry_points.append(FakeEntryPoint("banned_word", BannedWordValidator))
        assert "banned_word" not in discover_plugins()
        assert "banned_word" in discover_plugins(refresh=True)


class TestPolicyIntegration:
    def test_policy_uses_plugin_type(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        pipeline = build_pipeline(
            {
                "version": 1,
                "validators": [
                    {"type": "banned_word", "action": "block", "word": "kiwi"},
                ],
            }
        )
        result = pipeline.run("I like kiwi")
        assert result.blocked

    def test_policy_plugin_default_action(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        pipeline = build_pipeline(
            {"version": 1, "validators": [{"type": "banned_word"}]}
        )
        assert pipeline.validators[0][1] == Action.WARN

    def test_policy_unknown_type_lists_plugins(self) -> None:
        from llm_shelter.policy import PolicyError

        register_validator("banned_word", BannedWordValidator)
        with pytest.raises(PolicyError, match="Installed plugins: banned_word"):
            build_pipeline({"version": 1, "validators": [{"type": "nope"}]})

    def test_policy_plugin_bad_setting(self) -> None:
        from llm_shelter.policy import PolicyError

        register_validator("banned_word", BannedWordValidator)
        with pytest.raises(PolicyError, match=r"validators\[0\] \(banned_word\)"):
            build_pipeline(
                {"version": 1, "validators": [{"type": "banned_word", "bogus": 1}]}
            )

    def test_policy_plugin_invalid_action(self) -> None:
        from llm_shelter.policy import PolicyError

        register_validator("banned_word", BannedWordValidator)
        with pytest.raises(PolicyError, match="invalid action"):
            build_pipeline(
                {
                    "version": 1,
                    "validators": [{"type": "banned_word", "action": "explode"}],
                }
            )

    def test_policy_plugin_passthrough_rejected(self) -> None:
        from llm_shelter.policy import PolicyError

        register_validator("banned_word", BannedWordValidator)
        with pytest.raises(PolicyError, match="passthrough"):
            build_pipeline(
                {
                    "version": 1,
                    "validators": [{"type": "banned_word", "action": "passthrough"}],
                }
            )

    def test_policy_mixes_builtin_and_plugin(self) -> None:
        register_validator("banned_word", BannedWordValidator)
        pipeline = build_pipeline(
            {
                "version": 1,
                "validators": [
                    {"type": "pii", "action": "redact"},
                    {"type": "banned_word", "action": "warn", "word": "kiwi"},
                ],
            }
        )
        names = [v.name for v, _ in pipeline.validators]
        assert names == ["pii", "banned_word"]


class TestPluginInfo:
    def test_create_with_no_settings(self) -> None:
        info = PluginInfo(name="banned_word", factory=BannedWordValidator)
        validator = info.create()
        assert validator.word == "banana"


class TestPluginsCLI:
    def _cli(self):
        from llm_shelter.cli import _make_cli

        return _make_cli()

    def test_plugins_empty(self, fake_entry_points: list) -> None:
        from click.testing import CliRunner

        result = CliRunner().invoke(self._cli(), ["plugins"])
        assert result.exit_code == 0
        assert "No plugin validators installed" in result.output
        assert "Built-in validator types" in result.output

    def test_plugins_lists_registered(self, fake_entry_points: list) -> None:
        from click.testing import CliRunner

        register_validator("banned_word", BannedWordValidator)
        result = CliRunner().invoke(self._cli(), ["plugins"])
        assert result.exit_code == 0
        assert "banned_word" in result.output
        assert "warn" in result.output

    def test_plugins_json(self, fake_entry_points: list) -> None:
        from click.testing import CliRunner

        register_validator("banned_word", BannedWordValidator)
        result = CliRunner().invoke(self._cli(), ["plugins", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["plugins"][0]["name"] == "banned_word"
        assert data["plugins"][0]["default_action"] == "warn"
        assert "pii" in data["builtin"]
        assert data["errors"] == {}

    def test_plugins_load_error_exits_1(self, fake_entry_points: list) -> None:
        from click.testing import CliRunner

        fake_entry_points.append(FakeEntryPoint("broken", ImportError("no module")))
        result = CliRunner().invoke(self._cli(), ["plugins", "--json-output"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "broken" in data["errors"]
