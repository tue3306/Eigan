"""Resiliência: retry+backoff e circuit-breaker (§12.2). Sem espera/rede reais."""

from __future__ import annotations

import pytest

from eigan.engine.resilience import CircuitBreaker, CircuitOpen, RetryPolicy, retry


def test_backoff_is_exponential_and_capped() -> None:
    p = RetryPolicy(base_delay=1.0, factor=2.0, max_delay=10.0, jitter=0.0)
    assert p.delay_for(0) == 1.0
    assert p.delay_for(1) == 2.0
    assert p.delay_for(2) == 4.0
    assert p.delay_for(10) == 10.0  # capado em max_delay


def test_jitter_adds_proportional_random() -> None:
    p = RetryPolicy(base_delay=1.0, factor=1.0, jitter=0.5)
    assert p.delay_for(0, rand_value=1.0) == 1.5  # 1 + 1*0.5*1.0
    assert p.delay_for(0, rand_value=0.0) == 1.0


def test_retry_succeeds_after_transient_failures() -> None:
    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("transitorio")
        return "ok"

    out = retry(flaky, policy=RetryPolicy(max_attempts=3), sleep=lambda _: None, rand=lambda: 0.0)
    assert out == "ok" and calls["n"] == 3


def test_retry_reraises_after_max_attempts() -> None:
    def always_fail() -> None:
        raise RuntimeError("quebrado")

    with pytest.raises(RuntimeError, match="quebrado"):
        retry(
            always_fail, policy=RetryPolicy(max_attempts=2), sleep=lambda _: None, rand=lambda: 0.0
        )


def test_retry_does_not_swallow_non_retryable() -> None:
    def boom() -> None:
        raise KeyError("nao-transitorio")

    # só ValueError é retryable → KeyError propaga imediatamente (1 chamada).
    calls = {"n": 0}

    def wrapped() -> None:
        calls["n"] += 1
        boom()

    with pytest.raises(KeyError):
        retry(wrapped, retry_on=(ValueError,), sleep=lambda _: None)
    assert calls["n"] == 1


def test_circuit_breaker_opens_after_threshold_and_recovers() -> None:
    clock = {"t": 0.0}
    cb = CircuitBreaker(failure_threshold=2, cooldown=5.0, now=lambda: clock["t"])
    assert cb.state == "closed" and cb.allow()

    cb.record_failure()
    assert cb.state == "closed"  # 1 falha < threshold
    cb.record_failure()
    assert cb.state == "open" and not cb.allow()  # 2 falhas → abre

    clock["t"] = 5.0  # passou o cooldown
    assert cb.state == "half_open" and cb.allow()
    cb.record_success()
    assert cb.state == "closed"  # sucesso fecha e zera


def test_circuit_breaker_call_refuses_when_open() -> None:
    clock = {"t": 0.0}
    cb = CircuitBreaker(failure_threshold=1, cooldown=10.0, now=lambda: clock["t"])
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("falha")))  # 1 falha → abre
    assert not cb.allow()
    with pytest.raises(CircuitOpen):
        cb.call(lambda: "nunca chega aqui")  # recusa sem tentar o endpoint
