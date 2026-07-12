"""Sliding window rate limiting validator.

Caps requests per key (user, API key, IP, or a global bucket) before
they ever reach the LLM API, preventing abuse and runaway costs. The
underlying :class:`RateLimiter` is thread-safe and uses a monotonic
clock, so it is safe to share across request handlers.

Example::

    from llm_shelter.validators.ratelimit import RateLimitValidator

    validator = RateLimitValidator(max_requests=5, window_seconds=60)
    result = validator.validate("hello")   # allowed until 5 calls/minute
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable

from llm_shelter.pipeline import Action, Finding, ValidationResult


class RateLimiter:
    """Thread-safe sliding window rate limiter keyed by arbitrary strings.

    Each key gets its own window. Only allowed requests consume a slot,
    so rejected requests never extend a caller's lockout.

    Args:
        max_requests: Maximum allowed requests per window (must be >= 1).
        window_seconds: Window length in seconds (must be > 0).
        clock: Optional replacement for ``time.monotonic``, useful in tests.

    Raises:
        ValueError: If ``max_requests`` or ``window_seconds`` is out of range.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if max_requests < 1:
            raise ValueError(f"max_requests must be >= 1, got {max_requests}")
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be > 0, got {window_seconds}")
        self.max_requests = max_requests
        self.window_seconds = float(window_seconds)
        self._clock = clock or time.monotonic
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, hits: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def hit(self, key: str = "global") -> bool:
        """Record a request for *key* and return whether it is allowed.

        Returns:
            ``True`` when the request fits in the window (a slot is
            consumed), ``False`` when the key is currently rate limited.
        """
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            self._prune(hits, now)
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True

    def remaining(self, key: str = "global") -> int:
        """Return how many requests *key* has left in the current window."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                return self.max_requests
            self._prune(hits, now)
            return self.max_requests - len(hits)

    def retry_after(self, key: str = "global") -> float:
        """Return seconds until *key* frees a slot (0.0 if not limited)."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                return 0.0
            self._prune(hits, now)
            if len(hits) < self.max_requests:
                return 0.0
            return max(0.0, hits[0] + self.window_seconds - now)

    def reset(self, key: str | None = None) -> None:
        """Clear recorded requests for *key*, or every key when ``None``."""
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


class RateLimitValidator:
    """Block requests that exceed a sliding window rate limit.

    Fits the standard :class:`~llm_shelter.pipeline.Validator` protocol so
    it can be chained in a :class:`~llm_shelter.pipeline.GuardrailPipeline`
    ahead of expensive validators and LLM calls.

    By default all requests share one global bucket. Pass ``key_func`` to
    derive a bucket per caller (e.g. extract a user id from the text or
    close over request context).

    Args:
        max_requests: Maximum allowed requests per window.
        window_seconds: Window length in seconds.
        key: Static bucket name used when ``key_func`` is not given.
        key_func: Optional callable mapping the validated text to a bucket key.
        action: Action to take when the limit is exceeded.
        clock: Optional monotonic clock override, useful in tests.
    """

    name: str = "rate_limit"

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        key: str = "global",
        key_func: Callable[[str], str] | None = None,
        action: Action = Action.BLOCK,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.limiter = RateLimiter(max_requests, window_seconds, clock=clock)
        self.key = key
        self.key_func = key_func
        self.action = action

    def validate(self, text: str) -> ValidationResult:
        """Consume one rate limit slot for *text*'s bucket.

        Args:
            text: The input string being validated.

        Returns:
            A passing :class:`~llm_shelter.pipeline.ValidationResult` when
            the request fits in the window, otherwise a result with one
            ``rate_limited`` finding that includes the retry delay.
        """
        bucket = self.key_func(text) if self.key_func is not None else self.key
        allowed = self.limiter.hit(bucket)

        findings: list[Finding] = []
        if not allowed:
            retry = self.limiter.retry_after(bucket)
            findings.append(
                Finding(
                    validator=self.name,
                    category="rate_limited",
                    description=(
                        f"Rate limit exceeded for '{bucket}': "
                        f"{self.limiter.max_requests} requests per "
                        f"{self.limiter.window_seconds:g}s. "
                        f"Retry in {retry:.1f}s."
                    ),
                    severity=0.9,
                )
            )

        return ValidationResult(
            is_valid=len(findings) == 0,
            text=text,
            original_text=text,
            findings=findings,
            action_taken=self.action if findings else Action.PASSTHROUGH,
        )
