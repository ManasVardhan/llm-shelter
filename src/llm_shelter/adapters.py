"""Provider stream adapters for guardrails on OpenAI and Anthropic responses.

These helpers connect :class:`~llm_shelter.streaming.StreamGuard` to the
event objects emitted by the official ``openai`` and ``anthropic`` SDKs,
so applications guard token streams without writing extraction glue:

- :func:`openai_chunk_text` / :func:`anthropic_event_text` pull the text
  delta out of one stream event (returning ``""`` for non-text events).
- :func:`wrap_openai` / :func:`wrap_anthropic` adapt synchronous SDK
  streams and yield safe (redacted) text.
- :func:`awrap_openai` / :func:`awrap_anthropic` do the same for the
  async SDK clients, so async web apps guard token streams without
  threading glue.

Neither SDK is imported: events are handled structurally, and plain dicts
with the same shape (for example from a proxy or recorded fixtures) work
too. All wrappers raise :class:`~llm_shelter.streaming.StreamBlocked`
mid-iteration when a validator blocks, releasing nothing further.

Example::

    from llm_shelter import GuardrailPipeline, PIIValidator, StreamGuard
    from llm_shelter.adapters import awrap_openai
    from llm_shelter.pipeline import Action

    pipeline = GuardrailPipeline().add(PIIValidator(), Action.REDACT)
    stream = await client.chat.completions.create(..., stream=True)
    async for safe in awrap_openai(StreamGuard(pipeline), stream):
        yield safe
"""

from __future__ import annotations

from collections.abc import AsyncIterable, AsyncIterator, Callable, Iterable, Iterator
from typing import Any

from llm_shelter.pipeline import GuardrailPipeline
from llm_shelter.streaming import StreamGuard

__all__ = [
    "anthropic_event_text",
    "awrap_anthropic",
    "awrap_openai",
    "openai_chunk_text",
    "wrap_anthropic",
    "wrap_openai",
]


def _get(obj: Any, name: str) -> Any:
    """Read a field from an SDK object or a plain dict."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def openai_chunk_text(event: Any) -> str:
    """Return the text delta from an OpenAI chat completion chunk.

    Works with ``openai`` SDK ``ChatCompletionChunk`` objects and plain
    dicts of the same shape. Returns ``""`` for chunks without content
    (role deltas, tool calls, the final usage chunk).
    """
    choices = _get(event, "choices") or []
    if not choices:
        return ""
    delta = _get(choices[0], "delta")
    if delta is None:
        return ""
    content = _get(delta, "content")
    return content if isinstance(content, str) else ""


def anthropic_event_text(event: Any) -> str:
    """Return the text delta from an Anthropic messages stream event.

    Works with ``anthropic`` SDK ``MessageStreamEvent`` objects and plain
    dicts of the same shape. Only ``content_block_delta`` events carrying
    a ``text_delta`` produce text; everything else returns ``""``.
    """
    if _get(event, "type") != "content_block_delta":
        return ""
    delta = _get(event, "delta")
    if delta is None or _get(delta, "type") != "text_delta":
        return ""
    text = _get(delta, "text")
    return text if isinstance(text, str) else ""


def _as_guard(guard: StreamGuard | GuardrailPipeline) -> StreamGuard:
    if isinstance(guard, StreamGuard):
        return guard
    return StreamGuard(guard)


def _wrap_events(
    guard: StreamGuard | GuardrailPipeline,
    events: Iterable[Any],
    extract: Callable[[Any], str],
) -> Iterator[str]:
    active = _as_guard(guard)
    for event in events:
        text = extract(event)
        if not text:
            continue
        released = active.feed(text)
        if released:
            yield released
    released = active.finish()
    if released:
        yield released


async def _awrap_events(
    guard: StreamGuard | GuardrailPipeline,
    events: AsyncIterable[Any],
    extract: Callable[[Any], str],
) -> AsyncIterator[str]:
    active = _as_guard(guard)
    async for event in events:
        text = extract(event)
        if not text:
            continue
        released = active.feed(text)
        if released:
            yield released
    released = active.finish()
    if released:
        yield released


def wrap_openai(
    guard: StreamGuard | GuardrailPipeline, stream: Iterable[Any]
) -> Iterator[str]:
    """Yield safe text from a synchronous OpenAI chat completion stream.

    Accepts a :class:`StreamGuard` or a bare pipeline (a guard with the
    default holdback is created). Raises
    :class:`~llm_shelter.streaming.StreamBlocked` when a validator blocks.
    """
    return _wrap_events(guard, stream, openai_chunk_text)


def awrap_openai(
    guard: StreamGuard | GuardrailPipeline, stream: AsyncIterable[Any]
) -> AsyncIterator[str]:
    """Async counterpart of :func:`wrap_openai` for ``AsyncOpenAI`` streams."""
    return _awrap_events(guard, stream, openai_chunk_text)


def wrap_anthropic(
    guard: StreamGuard | GuardrailPipeline, stream: Iterable[Any]
) -> Iterator[str]:
    """Yield safe text from a synchronous Anthropic messages stream.

    Accepts a :class:`StreamGuard` or a bare pipeline (a guard with the
    default holdback is created). Raises
    :class:`~llm_shelter.streaming.StreamBlocked` when a validator blocks.
    """
    return _wrap_events(guard, stream, anthropic_event_text)


def awrap_anthropic(
    guard: StreamGuard | GuardrailPipeline, stream: AsyncIterable[Any]
) -> AsyncIterator[str]:
    """Async counterpart of :func:`wrap_anthropic` for ``AsyncAnthropic`` streams."""
    return _awrap_events(guard, stream, anthropic_event_text)
