"""Resiliência: retry com backoff+jitter e circuit-breaker (§12.2).

Scans são longos e dependem de ferramentas e provedores de IA instáveis. Uma falha
**transitória** não deve derrubar o scan inteiro nem desperdiçar o custo já gasto.
Este módulo é puro e determinístico onde importa: ``sleep`` e ``rand`` são injetáveis
(testes sem espera real), e o relógio do circuit-breaker também. Idempotência é
garantida a montante (UPSERT do store por ``fingerprint``): um passo reexecutado não
duplica finding.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

_T = TypeVar("_T")


@dataclass(frozen=True)
class RetryPolicy:
    """Política de retry: tentativas, backoff exponencial capado e jitter."""

    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    factor: float = 2.0
    jitter: float = 0.1  # fração do delay somada aleatoriamente (evita thundering herd)

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts deve ser >= 1")

    def delay_for(self, attempt: int, rand_value: float = 0.0) -> float:
        """Delay antes do retry ``attempt`` (0-indexed): ``base*factor^attempt``, capado
        em ``max_delay``, mais jitter proporcional. ``rand_value`` ∈ [0,1) é injetado."""
        raw = min(self.base_delay * (self.factor**attempt), self.max_delay)
        return raw + raw * self.jitter * rand_value


def retry(
    fn: Callable[[], _T],
    *,
    policy: RetryPolicy | None = None,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    sleep: Callable[[float], None] = time.sleep,
    rand: Callable[[], float] = random.random,
    on_retry: Callable[[int, BaseException], None] | None = None,
) -> _T:
    """Executa ``fn`` com retry: em exceção de ``retry_on``, espera (backoff+jitter) e
    tenta de novo, até ``max_attempts``. A última exceção propaga (falha não-transitória
    não é engolida). ``sleep``/``rand`` injetáveis para teste."""
    pol = policy or RetryPolicy()
    for attempt in range(pol.max_attempts):
        try:
            return fn()
        except retry_on as exc:
            if attempt == pol.max_attempts - 1:
                raise
            if on_retry is not None:
                on_retry(attempt, exc)
            sleep(pol.delay_for(attempt, rand()))
    raise AssertionError("inalcançável")  # pragma: no cover


class CircuitOpen(RuntimeError):
    """O circuito está aberto — a chamada é recusada sem tentar o endpoint quebrado."""


class CircuitBreaker:
    """Para de martelar um endpoint quebrado (§12.2).

    Após ``failure_threshold`` falhas consecutivas o circuito **abre** (recusa chamadas)
    por ``cooldown`` segundos; depois entra em **half-open** (deixa uma tentativa). Um
    sucesso **fecha**; uma falha em half-open reabre. O relógio (``now``) é injetável."""

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        cooldown: float = 30.0,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold deve ser >= 1")
        self._threshold = failure_threshold
        self._cooldown = cooldown
        self._now = now
        self._failures = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> str:
        if self._opened_at is None:
            return "closed"
        if self._now() - self._opened_at >= self._cooldown:
            return "half_open"
        return "open"

    def allow(self) -> bool:
        """True se uma chamada pode ser tentada agora (fechado ou half-open)."""
        return self.state != "open"

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = self._now()

    def call(self, fn: Callable[[], _T]) -> _T:
        """Executa ``fn`` sob o breaker: recusa (CircuitOpen) se aberto; registra o
        resultado. Recorra ao comportamento determinístico daquela etapa ao pegar
        ``CircuitOpen`` (P5) — o produto degrada, não trava."""
        if not self.allow():
            raise CircuitOpen("circuito aberto — endpoint em cooldown")
        try:
            result = fn()
        except Exception:
            self.record_failure()
            raise
        self.record_success()
        return result
