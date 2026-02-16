"""Function decorators for guarding LLM calls."""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from llm_shelter.pipeline import GuardrailPipeline, ValidationResult

F = TypeVar("F", bound=Callable[..., Any])


class GuardedCallError(Exception):
    """Raised when a guarded LLM call is blocked."""

    def __init__(self, result: ValidationResult) -> None:
        self.result = result
        categories = [f.category for f in result.findings]
        super().__init__(f"Blocked by guardrails: {', '.join(categories)}")


def guard_input(pipeline: GuardrailPipeline, param: str = "prompt") -> Callable[[F], F]:
    """Decorator to validate function input through a guardrail pipeline.

    Args:
        pipeline: The pipeline to run input through.
        param: Name of the keyword argument or first positional arg to validate.

    Raises:
        GuardedCallError: If the pipeline blocks the input.
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
    """Decorator to validate function output through a guardrail pipeline.

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
