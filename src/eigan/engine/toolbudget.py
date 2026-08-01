"""Orçamentos de tempo e recurso por ferramenta (§12.4).

O `Budget` do goal limita o scan como um todo (tempo/alvos/custo). Falta a fronteira
**por ferramenta**: uma ferramenta lenta não pode consumir o scan inteiro, e a saída de
uma ferramenta que processa dado hostil não pode crescer sem limite (contém parser
malicioso — liga ao §7.2). Este módulo dá as primitivas puras e testáveis:

- **`Deadline`** — prazo por ferramenta (relógio injetável), com ``remaining``/``expired``.
- **`cap_output`** — corta a saída num teto de bytes sem partir caractere UTF-8, sinaliza
  truncamento e preserva o tamanho original (transparência, P2).
- **`ToolLimits`** — configuração combinada (tempo + tamanho de saída) por ferramenta.

Limite de memória é dependente de SO (POSIX ``setrlimit``; Windows não expõe equivalente
direto) e fica para o wiring do runner por plataforma — não é fabricado aqui (P1).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class TruncatedOutput:
    """Saída possivelmente truncada, com o tamanho original preservado."""

    data: str
    truncated: bool
    original_bytes: int


def cap_output(text: str, max_bytes: int | None) -> TruncatedOutput:
    """Limita ``text`` a ``max_bytes`` bytes UTF-8 sem partir um caractere.

    ``max_bytes`` None ⇒ sem limite. O corte usa fronteira de caractere (decode com
    ``errors='ignore'`` do prefixo de bytes), então o resultado é sempre texto válido."""
    raw = text.encode("utf-8")
    original = len(raw)
    if max_bytes is None or original <= max_bytes:
        return TruncatedOutput(text, False, original)
    clipped = raw[:max_bytes].decode("utf-8", errors="ignore")
    return TruncatedOutput(clipped, True, original)


class Deadline:
    """Prazo de parede por ferramenta. O relógio (segundos monotônicos) é injetável."""

    def __init__(self, seconds: float | None, *, clock: Callable[[], float]) -> None:
        self._seconds = seconds
        self._clock = clock
        self._start = clock()

    def remaining(self) -> float | None:
        """Segundos restantes; ``None`` se não há prazo (sem limite)."""
        if self._seconds is None:
            return None
        return self._seconds - (self._clock() - self._start)

    def expired(self) -> bool:
        rem = self.remaining()
        return rem is not None and rem <= 0

    def timeout_arg(self) -> float | None:
        """Valor a passar como timeout do subprocess: o restante, nunca negativo."""
        rem = self.remaining()
        if rem is None:
            return None
        return max(0.0, rem)


@dataclass(frozen=True)
class ToolLimits:
    """Limites por ferramenta: prazo de parede e teto de tamanho de saída."""

    max_wall_seconds: float | None = None
    max_output_bytes: int | None = None

    def __post_init__(self) -> None:
        if self.max_wall_seconds is not None and self.max_wall_seconds <= 0:
            raise ValueError("max_wall_seconds deve ser > 0 ou None")
        if self.max_output_bytes is not None and self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes deve ser > 0 ou None")

    def deadline(self, *, clock: Callable[[], float]) -> Deadline:
        return Deadline(self.max_wall_seconds, clock=clock)

    def cap(self, text: str) -> TruncatedOutput:
        return cap_output(text, self.max_output_bytes)
