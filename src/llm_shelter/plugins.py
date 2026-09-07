"""Entry-point based validator plugins.

Third-party packages can ship their own validators and make them usable
by type name in policy files by declaring an entry point in the
``llm_shelter.validators`` group::

    # pyproject.toml of the plugin package
    [project.entry-points."llm_shelter.validators"]
    profanity = "my_pkg.validators:ProfanityValidator"

The entry point value must resolve to a factory (usually the validator
class itself) that returns an object satisfying the
:class:`~llm_shelter.pipeline.Validator` protocol when called with the
settings from the policy entry as keyword arguments::

    validators:
      - type: profanity
        action: block
        strictness: 0.8

Factories may set a ``default_action`` attribute (an
:class:`~llm_shelter.pipeline.Action` or its string value) to control
the action used when a policy entry omits ``action``; it defaults to
``block``. In-process registration is also supported via
:func:`register_validator`, which is handy for application-local
validators and tests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from typing import Any, cast

from llm_shelter.pipeline import Action, Validator

PLUGIN_GROUP = "llm_shelter.validators"


class PluginError(Exception):
    """Raised when a plugin cannot be loaded, registered, or constructed."""


@dataclass
class PluginInfo:
    """A discovered or registered plugin validator factory."""

    name: str
    factory: Callable[..., Any]
    source: str = ""
    default_action: Action = Action.BLOCK

    def create(self, settings: dict[str, Any] | None = None) -> Validator:
        """Instantiate the plugin validator with *settings* as kwargs.

        Raises:
            PluginError: If the factory raises or returns an object that
                does not satisfy the Validator protocol.
        """
        try:
            validator = self.factory(**(settings or {}))
        except PluginError:
            raise
        except Exception as exc:
            raise PluginError(
                f"Plugin validator '{self.name}' failed to construct: {exc}"
            ) from exc
        _check_validator(self.name, validator)
        return cast(Validator, validator)


def _check_validator(name: str, obj: Any) -> None:
    if not isinstance(obj, Validator) or not isinstance(getattr(obj, "name", None), str):
        raise PluginError(
            f"Plugin validator '{name}' returned {type(obj).__name__}, which does "
            "not satisfy the Validator protocol (needs a 'name' string attribute "
            "and a 'validate(text)' method)."
        )


def _default_action_of(name: str, factory: Callable[..., Any]) -> Action:
    raw = getattr(factory, "default_action", Action.BLOCK)
    if isinstance(raw, Action):
        action = raw
    else:
        try:
            action = Action(str(raw).lower())
        except ValueError as exc:
            raise PluginError(
                f"Plugin validator '{name}' declares invalid default_action {raw!r}. "
                "Allowed: block, warn, redact"
            ) from exc
    if action == Action.PASSTHROUGH:
        raise PluginError(
            f"Plugin validator '{name}' declares default_action 'passthrough', "
            "which is not allowed."
        )
    return action


def _builtin_types() -> tuple[str, ...]:
    from llm_shelter.policy import SUPPORTED_TYPES

    return SUPPORTED_TYPES


_registered: dict[str, PluginInfo] = {}
_entry_point_cache: dict[str, PluginInfo] | None = None
_entry_point_errors: dict[str, str] = {}


def register_validator(
    name: str,
    factory: Callable[..., Any],
    default_action: Action | str | None = None,
    replace: bool = False,
) -> PluginInfo:
    """Register a validator factory in process, without an entry point.

    Args:
        name: The type name usable in policy files.
        factory: Callable returning a Validator when called with the
            policy entry settings as keyword arguments.
        default_action: Action used when a policy entry omits ``action``
            (defaults to the factory's ``default_action`` attribute, or
            block).
        replace: Allow replacing an existing registration.

    Raises:
        PluginError: If the name is empty, shadows a built-in validator
            type, or is already registered without *replace*.
    """
    if not name or not name.strip():
        raise PluginError("Plugin validator name must be a non-empty string")
    name = name.strip()
    if name in _builtin_types():
        raise PluginError(
            f"Plugin validator name '{name}' shadows a built-in validator type"
        )
    if name in _registered and not replace:
        raise PluginError(
            f"Plugin validator '{name}' is already registered. "
            "Pass replace=True to replace it."
        )
    if default_action is None:
        action = _default_action_of(name, factory)
    elif isinstance(default_action, Action):
        action = default_action
    else:
        try:
            action = Action(str(default_action).lower())
        except ValueError as exc:
            raise PluginError(
                f"Invalid default_action {default_action!r} for plugin '{name}'. "
                "Allowed: block, warn, redact"
            ) from exc
    if action == Action.PASSTHROUGH:
        raise PluginError(
            f"default_action 'passthrough' is not allowed for plugin '{name}'"
        )
    info = PluginInfo(
        name=name,
        factory=factory,
        source="registered",
        default_action=action,
    )
    _registered[name] = info
    return info


def unregister_validator(name: str) -> None:
    """Remove an in-process registration made with :func:`register_validator`.

    Raises:
        PluginError: If the name was not registered.
    """
    if name not in _registered:
        raise PluginError(f"Plugin validator '{name}' is not registered")
    del _registered[name]


def _load_entry_points(refresh: bool = False) -> dict[str, PluginInfo]:
    global _entry_point_cache
    if _entry_point_cache is not None and not refresh:
        return _entry_point_cache

    plugins: dict[str, PluginInfo] = {}
    _entry_point_errors.clear()
    builtin = _builtin_types()
    for ep in metadata.entry_points(group=PLUGIN_GROUP):
        name = ep.name
        if name in builtin:
            _entry_point_errors[name] = "shadows a built-in validator type; ignored"
            continue
        try:
            factory = ep.load()
            info = PluginInfo(
                name=name,
                factory=factory,
                source=getattr(ep, "value", "") or "entry point",
                default_action=_default_action_of(name, factory),
            )
        except PluginError as exc:
            _entry_point_errors[name] = str(exc)
            continue
        except Exception as exc:  # noqa: BLE001 - third-party entry points may raise anything
            _entry_point_errors[name] = f"failed to load: {exc}"
            continue
        plugins[name] = info

    _entry_point_cache = plugins
    return plugins


def discover_plugins(refresh: bool = False) -> dict[str, PluginInfo]:
    """Return all available plugin validators by name.

    Combines entry points from installed packages (cached after the
    first call; pass ``refresh=True`` to re-scan) with in-process
    registrations, which take precedence on name clashes.
    """
    plugins = dict(_load_entry_points(refresh=refresh))
    plugins.update(_registered)
    return plugins


def plugin_load_errors() -> dict[str, str]:
    """Return entry points that failed to load, mapped to error messages."""
    _load_entry_points()
    return dict(_entry_point_errors)


def get_plugin(name: str) -> PluginInfo | None:
    """Return the plugin registered under *name*, or None."""
    return discover_plugins().get(name)


def create_validator(name: str, settings: dict[str, Any] | None = None) -> Validator:
    """Instantiate the plugin validator *name* with *settings* as kwargs.

    Raises:
        PluginError: If no such plugin exists or construction fails.
    """
    info = get_plugin(name)
    if info is None:
        known = ", ".join(sorted(discover_plugins())) or "none installed"
        raise PluginError(
            f"No plugin validator named '{name}' (available plugins: {known})"
        )
    return info.create(settings)
