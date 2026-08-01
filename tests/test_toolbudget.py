"""Orçamentos de tempo e recurso por ferramenta (§12.4).

Falha antes / passa depois: a saída é capada no teto de bytes sem partir caractere
UTF-8 (com flag de truncamento e tamanho original), e o prazo por ferramenta expira e
expõe o restante como timeout de subprocess.
"""

from __future__ import annotations

import pytest

from eigan.engine.toolbudget import Deadline, ToolLimits, cap_output


class _FakeClock:
    """Relógio monotônico controlado (segundos)."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_cap_output_below_limit_is_untouched() -> None:
    out = cap_output("abc", 100)
    assert out.data == "abc" and out.truncated is False and out.original_bytes == 3


def test_cap_output_truncates_and_reports_original() -> None:
    out = cap_output("a" * 1000, 10)
    assert len(out.data) == 10
    assert out.truncated is True
    assert out.original_bytes == 1000


def test_cap_output_does_not_split_utf8_character() -> None:
    # "é" ocupa 2 bytes; cortar em 3 bytes não pode devolver meio caractere
    text = "é" * 5  # 10 bytes
    out = cap_output(text, 3)
    assert out.data == "é"  # 2 bytes válidos, o 3º byte parcial é descartado
    assert out.truncated is True


def test_cap_output_none_means_no_limit() -> None:
    out = cap_output("x" * 5000, None)
    assert out.truncated is False and len(out.data) == 5000


def test_deadline_remaining_and_expired() -> None:
    clock = _FakeClock()
    deadline = Deadline(10.0, clock=clock)
    assert deadline.remaining() == 10.0
    clock.t = 4.0
    assert deadline.remaining() == 6.0
    assert deadline.expired() is False
    clock.t = 10.0
    assert deadline.expired() is True
    assert deadline.timeout_arg() == 0.0  # nunca negativo


def test_deadline_without_limit_never_expires() -> None:
    clock = _FakeClock()
    deadline = Deadline(None, clock=clock)
    clock.t = 1_000_000.0
    assert deadline.remaining() is None
    assert deadline.expired() is False
    assert deadline.timeout_arg() is None


def test_tool_limits_validation_and_helpers() -> None:
    with pytest.raises(ValueError):
        ToolLimits(max_wall_seconds=0)
    with pytest.raises(ValueError):
        ToolLimits(max_output_bytes=-1)
    limits = ToolLimits(max_wall_seconds=5, max_output_bytes=4)
    assert limits.cap("abcdef").truncated is True
    clock = _FakeClock()
    assert limits.deadline(clock=clock).remaining() == 5.0
