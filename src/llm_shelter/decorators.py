"""Function decorators for guarding LLM calls.

Wrap any function that accepts or returns text with :func:`guard_input`
or :func:`guard_output` to automatically run it through a
:class:`~llm_shelter.pipeline.GuardrailPipeline`. Blocked calls raise
:class:`GuardedCallError`; redacted text is forwarded transparently.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from llm_shelter.pipeline import GuardrailPipeline, ValidationResult

F = TypeVar("F", bound=Callable[..., Any])


class GuardedCallError(Exception):
    """Raised when a guarded LLM call is blocked by the pipeline.

    Attributes:
        result: The :class:`~llm_shelter.pipeline.ValidationResult` that
            triggered the block, giving access to all findings.
    """

    def __init__(self, result: ValidationResult) -> None:
        self.result = result
        categories = [f.category for f in result.findings]
        super().__init__(f"Blocked by guardrails: {', '.join(categories)}")


def guard_input(pipeline: GuardrailPipeline, param: str = "prompt") -> Callable[[F], F]:
    """Decorator that validates function input through a guardrail pipeline.

    The decorator inspects the keyword argument named *param* (falling back
    to the first positional argument). If the pipeline blocks the text,
    :class:`GuardedCallError` is raised before the wrapped function runs.
    If the pipeline redacts the text, the modified version is forwarded.

    Args:
        pipeline: The :class:`~llm_shelter.pipeline.GuardrailPipeline` to
            run input through.
        param: Name of the keyword argument to validate. Defaults to
            ``"prompt"``.

    Returns:
        A decorator that wraps the target function.

    Raises:
        GuardedCallError: If the pipeline blocks the input.

    Example::

        pipeline = GuardrailPipeline().add(InjectionValidator(), Action.BLOCK)

        @guard_input(pipeline)
        def ask_llm(prompt: str) -> str:
            return call_api(prompt)
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            text = kwargs.get(param)
            if text is None and args:
                text = args[0]

            if isinstance(text, str):
                result = pipeline.run(text)
                if result.blocked:
                    raise GuardedCallError(result)
                if result.text != result.original_text:
                    if param in kwargs:
                        kwargs[param] = result.text
                    elif args:
                        args = (result.text, *args[1:])

            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def guard_output(pipeline: GuardrailPipeline) -> Callable[[F], F]:
    """Decorator that validates function output through a guardrail pipeline.

    The wrapped function is called normally. If it returns a string, the
    pipeline runs on that string. Blocked output raises
    :class:`GuardedCallError`; redacted output is returned transparently.
    Non-string return values pass through unchanged.

    Args:
        pipeline: The :class:`~llm_shelter.pipeline.GuardrailPipeline` to
            run output through.

    Returns:
        A decorator that wraps the target function.

    Raises:
        GuardedCallError: If the pipeline blocks the output.
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            output = fn(*args, **kwargs)

            if isinstance(output, str):
                result = pipeline.run(output)
                if result.blocked:
                    raise GuardedCallError(result)
                return result.text

            return output

        return wrapper  # type: ignore[return-value]

    return decorator
