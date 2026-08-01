"""Kill switch / parada de emergência (§18.2).

Requisito real de engajamento: algo deu errado no alvo do cliente → **para agora**. O
cancelamento cooperativo por evento do `ScanManager` (API) só aborta no próximo ponto
de emissão — uma ferramenta externa longa (ex.: um nmap) seguiria rodando. O kill
switch cobre essa lacuna: um sinal **thread-safe** que, ao ser acionado,

1. registra o **motivo** e o instante (para a trilha §18.3);
2. executa os **cleanups** registrados (encerrar ferramentas em execução com
   ``terminate`` → espera → ``kill``);
3. faz os checkpoints cooperativos (`check()`) levantarem `ScanAborted`, para o engine
   persistir estado resume-safe (§12.1) e encerrar.

É usável tanto pelo CLI quanto pela API (um mesmo objeto compartilhado). Fail-safe: o
**primeiro** motivo vence; cleanups rodam **uma única vez**; um cleanup que falhe não
impede os demais (melhor esforço para encerrar tudo).
"""

from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol

log = logging.getLogger(__name__)


class ScanAborted(RuntimeError):
    """Levantada num checkpoint cooperativo quando o kill switch está acionado."""


class Terminable(Protocol):
    """Processo externo encerrável (compatível com ``subprocess.Popen``)."""

    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...


def terminate_process(proc: Terminable, *, grace: float = 5.0) -> None:
    """Encerra um processo com limpeza: ``terminate`` → espera ``grace`` → ``kill``.

    Idempotente para processo já encerrado (``poll()`` != None)."""
    if proc.poll() is not None:
        return  # já saiu — nada a fazer
    proc.terminate()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()  # não respeitou o terminate → força


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class KillSwitch:
    """Sinal de parada de emergência, thread-safe e compartilhável (CLI + API)."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._event = threading.Event()
        self._lock = threading.RLock()
        self._clock = clock or _now_utc
        self._reason: str | None = None
        self._triggered_at: datetime | None = None
        self._cleanups: list[Callable[[], None]] = []

    @property
    def is_active(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason

    @property
    def triggered_at(self) -> datetime | None:
        return self._triggered_at

    def check(self) -> None:
        """Levanta :class:`ScanAborted` se o switch estiver acionado (checkpoint)."""
        if self._event.is_set():
            raise ScanAborted(self._reason or "parada de emergência acionada")

    def on_abort(self, cleanup: Callable[[], None]) -> None:
        """Registra um cleanup a rodar no acionamento. Se já acionado, roda na hora
        (registro tardio de uma ferramenta que subiu depois do trigger)."""
        with self._lock:
            if self._event.is_set():
                self._run_one(cleanup)
            else:
                self._cleanups.append(cleanup)

    def register_process(self, proc: Terminable, *, grace: float = 5.0) -> None:
        """Registra um processo externo para ser encerrado no acionamento."""
        self.on_abort(lambda: terminate_process(proc, grace=grace))

    def trigger(self, reason: str, *, at: datetime | None = None) -> bool:
        """Aciona a parada. Idempotente: só o 1º trigger registra motivo e roda os
        cleanups. Devolve ``True`` se este foi o acionamento efetivo."""
        with self._lock:
            if self._event.is_set():
                return False
            self._reason = reason
            self._triggered_at = at or self._clock()
            self._event.set()
            pending, self._cleanups = self._cleanups, []
        log.warning("kill switch acionado", extra={"event": "kill_switch", "reason": reason})
        for cleanup in pending:
            self._run_one(cleanup)
        return True

    @staticmethod
    def _run_one(cleanup: Callable[[], None]) -> None:
        try:
            cleanup()
        except Exception:  # noqa: BLE001 — melhor esforço: um cleanup não derruba os outros
            log.exception("falha ao executar cleanup do kill switch")
