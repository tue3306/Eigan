"""Kill switch / parada de emergência (§18.2).

Falha antes / passa depois: acionar o switch registra motivo/instante, roda os cleanups
uma única vez, encerra processos em execução (terminate→kill) e faz os checkpoints
levantarem ScanAborted. Fail-safe: 1º motivo vence; cleanup que falha não bloqueia os
demais; registro tardio ainda é limpo.
"""

from __future__ import annotations

import subprocess
import threading
from datetime import datetime, timezone

import pytest

from eigan.engine.killswitch import KillSwitch, ScanAborted, terminate_process


class _FakeProc:
    """Processo falso compatível com Terminable, registrando as chamadas."""

    def __init__(self, *, running: bool = True, wait_times_out: bool = False) -> None:
        self._running = running
        self._wait_times_out = wait_times_out
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return None if self._running else 0

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True
        self._running = False

    def wait(self, timeout: float | None = None) -> int:
        if self._wait_times_out:
            raise subprocess.TimeoutExpired(cmd="tool", timeout=timeout or 0)
        self._running = False
        return 0


def test_check_raises_only_after_trigger() -> None:
    ks = KillSwitch()
    ks.check()  # não acionado — no-op
    ks.trigger("alvo instável")
    with pytest.raises(ScanAborted):
        ks.check()
    assert ks.is_active is True
    assert ks.reason == "alvo instável"


def test_first_reason_wins_and_cleanups_run_once() -> None:
    ks = KillSwitch()
    calls: list[str] = []
    ks.on_abort(lambda: calls.append("a"))
    first = ks.trigger("motivo-1")
    second = ks.trigger("motivo-2")
    assert first is True and second is False  # idempotente
    assert ks.reason == "motivo-1"  # 1º motivo vence
    assert calls == ["a"]  # cleanup rodou uma única vez


def test_triggered_at_uses_injected_clock() -> None:
    fixed = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
    ks = KillSwitch(clock=lambda: fixed)
    ks.trigger("x")
    assert ks.triggered_at == fixed


def test_running_process_is_terminated() -> None:
    ks = KillSwitch()
    proc = _FakeProc(running=True)
    ks.register_process(proc)
    ks.trigger("parar")
    assert proc.terminated is True
    assert proc.killed is False  # respeitou o terminate


def test_stubborn_process_is_killed() -> None:
    ks = KillSwitch()
    proc = _FakeProc(running=True, wait_times_out=True)
    ks.register_process(proc, grace=0.01)
    ks.trigger("parar")
    assert proc.terminated is True
    assert proc.killed is True  # não respondeu ao terminate → kill


def test_finished_process_is_left_alone() -> None:
    proc = _FakeProc(running=False)
    terminate_process(proc)
    assert proc.terminated is False and proc.killed is False


def test_late_registration_after_trigger_runs_immediately() -> None:
    ks = KillSwitch()
    ks.trigger("já acionado")
    proc = _FakeProc(running=True)
    ks.register_process(proc)  # registrado DEPOIS do trigger
    assert proc.terminated is True  # limpo na hora


def test_failing_cleanup_does_not_block_others() -> None:
    ks = KillSwitch()
    calls: list[str] = []

    def boom() -> None:
        raise RuntimeError("cleanup quebrou")

    ks.on_abort(boom)
    ks.on_abort(lambda: calls.append("ok"))
    ks.trigger("parar")  # não propaga a exceção
    assert calls == ["ok"]  # o cleanup seguinte ainda rodou


def test_concurrent_trigger_runs_cleanup_once() -> None:
    ks = KillSwitch()
    counter = {"n": 0}
    lock = threading.Lock()

    def inc() -> None:
        with lock:
            counter["n"] += 1

    ks.on_abort(inc)
    threads = [threading.Thread(target=lambda: ks.trigger("corrida")) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert counter["n"] == 1  # apenas um trigger efetivo, apesar da corrida
    assert ks.is_active is True
