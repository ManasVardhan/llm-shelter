"""Streaming guardrails for incremental LLM output validation.

:class:`StreamGuard` wraps a :class:`~llm_shelter.pipeline.GuardrailPipeline`
so guardrails work with token streaming instead of waiting for the full
response. Chunks are fed in as they arrive, validated incrementally, and
safe (redacted) text is released as soon as it is known to be clean. The
moment a validator blocks, :class:`StreamBlocked` is raised and nothing
further is released, so callers can cut the stream immediately.

To handle findings that straddle chunk boundaries, the guard keeps a
holdback window of unreleased text at the end of the stream. Text is only
released once it is at least ``holdback`` characters behind the newest
chunk, and the release point is moved back further when a finding overlaps
it, so redactions apply across chunk boundaries. Patterns longer than the
holdback window may still be split by a release; increase ``holdback``
when scanning for long secrets.

Example::

    from llm_shelter import GuardrailPipeline, PIIValidator, StreamGuard
    from llm_shelter.pipeline import Action

    pipeline = GuardrailPipeline().add(PIIValidator(), Action.REDACT)
    guard = StreamGuard(pipeline)
    for chunk in llm_stream:
        print(guard.feed(chunk), end="")
    print(guard.finish(), end="")

Or wrap an iterator directly::

    for safe_chunk in StreamGuard(pipeline).wrap(llm_stream):
        print(safe_chunk, end="")

Note:
    The pipeline's validators are re-run on the unreleased tail as it
    grows, so stateful validators such as
    :class:`~llm_shelter.validators.ratelimit.RateLimitValidator` should
    not be part of a streamed pipeline: apply rate limiting once per
    request instead.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterable, AsyncIterator, Iterable, Iterator
from typing import Any

from llm_shelter.pipeline import (
    Action,
    Finding,
    GuardrailPipeline,
    ValidationResult,
)

DEFAULT_HOLDBACK = 64

_SEVERITY = {
    Action.PASSTHROUGH: 0,
    Action.WARN: 1,
    Action.REDACT: 2,
    Action.BLOCK: 3,
}


class StreamBlocked(Exception):
    """Raised when a validator blocks the stream.

    Attributes:
        findings: The findings that caused the block.
    """

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        detail = ", ".join(
            f"{f.validator}/{f.category}" for f in findings[:3]
        ) or "unknown"
        super().__init__(f"Stream blocked by guardrails ({detail})")


class StreamGuard:
    """Incrementally validate streamed text through a guardrail pipeline.

    Args:
        pipeline: The pipeline whose validators and actions to apply.
            If it has an audit logger attached, one aggregate record is
            written when the stream finishes or blocks.
        holdback: Number of trailing characters withheld from release
            until more text arrives, so findings spanning chunk
            boundaries are caught before their text is released.
    """

    def __init__(
        self,
        pipeline: GuardrailPipeline,
        holdback: int = DEFAULT_HOLDBACK,
    ) -> None:
        if holdback < 1:
            raise ValueError("holdback must be at least 1 character")
        self._pipeline = pipeline
        self.holdback = holdback
        # Audit-free clone: per-chunk scans should not spam the audit log.
        self._scan = GuardrailPipeline()
        for validator, action in pipeline.validators:
            self._scan.add(validator, action)
        self._buffer = ""
        self._released = ""
        self._raw = ""
        self._findings: list[Finding] = []
        self._action = Action.PASSTHROUGH
        self._blocked = False
        self._closed = False
        self._started = time.perf_counter()
        self._context: dict[str, Any] | None = None

    @property
    def blocked(self) -> bool:
        """Return ``True`` once a validator has blocked the stream."""
        return self._blocked

    @property
    def released(self) -> str:
        """All safe text released so far."""
        return self._released

    @property
    def findings(self) -> list[Finding]:
        """Findings recorded for released text (and the block, if any)."""
        return list(self._findings)

    @property
    def result(self) -> ValidationResult:
        """Aggregate result for the stream so far.

        After :meth:`finish` this covers the whole stream; before that it
        covers the text processed so far.
        """
        return ValidationResult(
            is_valid=not self._blocked and self._action != Action.BLOCK,
            text=self._released,
            original_text=self._raw,
            findings=list(self._findings),
            action_taken=self._action,
        )

    def feed(self, chunk: str, context: dict[str, Any] | None = None) -> str:
        """Feed one chunk of streamed text and return newly released safe text.

        Args:
            chunk: The next piece of streamed output.
            context: Optional caller metadata attached to the aggregate
                audit record (last value wins).

        Returns:
            Safe (possibly redacted) text that can be forwarded now. May
            be empty while text is withheld in the holdback window.

        Raises:
            StreamBlocked: If a validator blocks; the stream must stop.
            RuntimeError: If called after ``finish()`` or after a block.
        """
        self._ensure_open()
        if context is not None:
            self._context = context
        self._buffer += chunk
        self._raw += chunk

        full = self._scan.run(self._buffer)
        if full.blocked:
            self._block(full.findings)

        cut = len(self._buffer) - self.holdback
        for finding in full.findings:
            if finding.span and finding.span[0] < cut < finding.span[1]:
                cut = min(cut, finding.span[0])
        if cut <= 0:
            return ""

        prefix_result = self._scan.run(self._buffer[:cut])
        if prefix_result.blocked:
            self._block(prefix_result.findings)

        self._buffer = self._buffer[cut:]
        self._record(prefix_result)
        return prefix_result.text

    def finish(self) -> str:
        """Flush and validate the remaining held-back text.

        Returns:
            The final piece of safe text (may be empty).

        Raises:
            StreamBlocked: If the remaining text triggers a block.
            RuntimeError: If called after ``finish()`` or after a block.
        """
        self._ensure_open()
        tail = self._scan.run(self._buffer) if self._buffer else None
        if tail is not None and tail.blocked:
            self._block(tail.findings)
        self._buffer = ""
        released = ""
        if tail is not None:
            self._record(tail)
            released = tail.text
        self._closed = True
        self._emit_audit()
        return released

    def wrap(self, chunks: Iterable[str]) -> Iterator[str]:
        """Yield safe text for each incoming chunk, then the final flush.

        Empty releases are skipped, so consumers only see text that can
        be forwarded. Raises :class:`StreamBlocked` mid-iteration when a
        validator blocks.
        """
        for chunk in chunks:
            released = self.feed(chunk)
            if released:
                yield released
        released = self.finish()
        if released:
            yield released

    async def awrap(self, chunks: AsyncIterable[str]) -> AsyncIterator[str]:
        """Async counterpart of :meth:`wrap` for async chunk iterators.

        Yields safe text for each incoming chunk, then the final flush,
        skipping empty releases. Raises :class:`StreamBlocked`
        mid-iteration when a validator blocks. Validation itself runs
        synchronously between awaits; it is regex work on the unreleased
        tail, which is fast enough not to starve the event loop.

        Example::

            guard = StreamGuard(pipeline)
            async for safe in guard.awrap(llm_stream):
                await response.write(safe)
        """
        async for chunk in chunks:
            released = self.feed(chunk)
            if released:
                yield released
        released = self.finish()
        if released:
            yield released

    def _ensure_open(self) -> None:
        if self._blocked:
            raise RuntimeError("Stream is blocked; no further text is accepted")
        if self._closed:
            raise RuntimeError("Stream already finished")

    def _record(self, result: ValidationResult) -> None:
        self._released += result.text
        self._findings.extend(result.findings)
        if _SEVERITY[result.action_taken] > _SEVERITY[self._action]:
            self._action = result.action_taken

    def _block(self, findings: list[Finding]) -> None:
        self._findings.extend(findings)
        self._action = Action.BLOCK
        self._blocked = True
        self._closed = True
        self._emit_audit()
        raise StreamBlocked(findings)

    def _emit_audit(self) -> None:
        """Write one aggregate audit record if the pipeline has a logger."""
        if self._pipeline.audit is None:
            return
        from llm_shelter.auditlog import build_record

        record = build_record(
            self.result,
            validators=[
                {"name": validator.name, "action": action.value}
                for validator, action in self._pipeline.validators
            ],
            latency_ms=(time.perf_counter() - self._started) * 1000,
            context=self._context,
        )
        self._pipeline.audit.log(record)
