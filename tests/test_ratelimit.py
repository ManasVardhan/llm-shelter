"""Tests for the sliding window rate limiter and its validator."""

from __future__ import annotations

import threading

import pytest

from llm_shelter import GuardrailPipeline, RateLimiter, RateLimitValidator
from llm_shelter.pipeline import Action


class FakeClock:
    """Deterministic monotonic clock for testing window behavior."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestRateLimiter:
    def test_allows_up_to_max_requests(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60, clock=FakeClock())
        assert limiter.hit("u1") is True
        assert limiter.hit("u1") is True
        assert limiter.hit("u1") is True
        assert limiter.hit("u1") is False

    def test_window_slides_and_frees_slots(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=2, window_seconds=10, clock=clock)
        assert limiter.hit("u1")
        clock.advance(5)
        assert limiter.hit("u1")
        assert not limiter.hit("u1")
        clock.advance(6)  # first hit (t=1000) now outside the 10s window
        assert limiter.hit("u1")

    def test_keys_are_independent(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60, clock=FakeClock())
        assert limiter.hit("alice")
        assert not limiter.hit("alice")
        assert limiter.hit("bob")

    def test_rejected_requests_do_not_consume_slots(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=1, window_seconds=10, clock=clock)
        assert limiter.hit("u1")
        for _ in range(5):
            assert not limiter.hit("u1")
        clock.advance(11)
        # If rejections consumed slots, this would still be limited
        assert limiter.hit("u1")

    def test_remaining_counts_down(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60, clock=FakeClock())
        assert limiter.remaining("u1") == 3
        limiter.hit("u1")
        assert limiter.remaining("u1") == 2
        limiter.hit("u1")
        limiter.hit("u1")
        assert limiter.remaining("u1") == 0

    def test_remaining_recovers_after_window(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=2, window_seconds=10, clock=clock)
        limiter.hit("u1")
        limiter.hit("u1")
        clock.advance(11)
        assert limiter.remaining("u1") == 2

    def test_retry_after_zero_when_not_limited(self):
        limiter = RateLimiter(max_requests=2, window_seconds=10, clock=FakeClock())
        assert limiter.retry_after("u1") == 0.0
        limiter.hit("u1")
        assert limiter.retry_after("u1") == 0.0

    def test_retry_after_reports_time_until_slot_frees(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=1, window_seconds=10, clock=clock)
        limiter.hit("u1")
        clock.advance(3)
        assert limiter.retry_after("u1") == pytest.approx(7.0)

    def test_reset_single_key(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60, clock=FakeClock())
        limiter.hit("a")
        limiter.hit("b")
        limiter.reset("a")
        assert limiter.hit("a")
        assert not limiter.hit("b")

    def test_reset_all_keys(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60, clock=FakeClock())
        limiter.hit("a")
        limiter.hit("b")
        limiter.reset()
        assert limiter.hit("a")
        assert limiter.hit("b")

    def test_reset_unknown_key_is_noop(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60, clock=FakeClock())
        limiter.reset("ghost")

    def test_invalid_max_requests_raises(self):
        with pytest.raises(ValueError, match="max_requests"):
            RateLimiter(max_requests=0, window_seconds=60)

    def test_invalid_window_raises(self):
        with pytest.raises(ValueError, match="window_seconds"):
            RateLimiter(max_requests=1, window_seconds=0)

    def test_thread_safety_no_overadmission(self):
        limiter = RateLimiter(max_requests=50, window_seconds=60)
        allowed = []

        def worker():
            for _ in range(20):
                if limiter.hit("shared"):
                    allowed.append(1)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(allowed) == 50


class TestRateLimitValidator:
    def test_allows_within_limit(self):
        validator = RateLimitValidator(max_requests=2, window_seconds=60, clock=FakeClock())
        result = validator.validate("hello")
        assert result.is_valid
        assert result.findings == []
        assert result.action_taken == Action.PASSTHROUGH

    def test_blocks_over_limit(self):
        validator = RateLimitValidator(max_requests=1, window_seconds=60, clock=FakeClock())
        assert validator.validate("one").is_valid
        result = validator.validate("two")
        assert not result.is_valid
        assert result.action_taken == Action.BLOCK
        assert result.findings[0].category == "rate_limited"
        assert "Retry in" in result.findings[0].description

    def test_text_passes_through_unmodified(self):
        validator = RateLimitValidator(max_requests=1, window_seconds=60, clock=FakeClock())
        validator.validate("x")
        result = validator.validate("sensitive text")
        assert result.text == "sensitive text"
        assert result.original_text == "sensitive text"

    def test_key_func_buckets_by_caller(self):
        validator = RateLimitValidator(
            max_requests=1,
            window_seconds=60,
            key_func=lambda text: text.split(":")[0],
            clock=FakeClock(),
        )
        assert validator.validate("alice:hi").is_valid
        assert validator.validate("bob:hi").is_valid
        assert not validator.validate("alice:again").is_valid

    def test_static_key_shares_bucket(self):
        clock = FakeClock()
        validator = RateLimitValidator(max_requests=1, window_seconds=60, key="tenant-1", clock=clock)
        assert validator.validate("a").is_valid
        assert not validator.validate("b").is_valid

    def test_recovers_after_window(self):
        clock = FakeClock()
        validator = RateLimitValidator(max_requests=1, window_seconds=10, clock=clock)
        assert validator.validate("a").is_valid
        assert not validator.validate("b").is_valid
        clock.advance(11)
        assert validator.validate("c").is_valid

    def test_warn_action_keeps_result_valid(self):
        validator = RateLimitValidator(
            max_requests=1, window_seconds=60, action=Action.WARN, clock=FakeClock()
        )
        validator.validate("a")
        result = validator.validate("b")
        assert result.action_taken == Action.WARN
        assert result.findings

    def test_finding_mentions_bucket_and_limits(self):
        validator = RateLimitValidator(
            max_requests=1, window_seconds=30, key="ip-1.2.3.4", clock=FakeClock()
        )
        validator.validate("a")
        desc = validator.validate("b").findings[0].description
        assert "ip-1.2.3.4" in desc
        assert "1 requests per 30s" in desc

    def test_limiter_exposed_for_inspection(self):
        validator = RateLimitValidator(max_requests=5, window_seconds=60, clock=FakeClock())
        validator.validate("a")
        assert validator.limiter.remaining("global") == 4

    def test_in_pipeline_blocks_before_later_validators(self):
        calls = []

        class SpyValidator:
            name = "spy"

            def validate(self, text):
                calls.append(text)
                from llm_shelter.pipeline import ValidationResult

                return ValidationResult(is_valid=True, text=text, original_text=text)

        pipeline = GuardrailPipeline()
        pipeline.add(RateLimitValidator(max_requests=1, window_seconds=60, clock=FakeClock()))
        pipeline.add(SpyValidator())

        assert pipeline.run("first").is_valid
        blocked = pipeline.run("second")
        assert blocked.blocked
        assert calls == ["first"]

    def test_default_configuration(self):
        validator = RateLimitValidator()
        assert validator.limiter.max_requests == 60
        assert validator.limiter.window_seconds == 60.0
        assert validator.name == "rate_limit"
