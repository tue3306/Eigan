"""Classificação da informação por engajamento (§10.4).

Cada engajamento (e cada finding) pode carregar uma classificação de sensibilidade,
propagada a relatório, export e controle de acesso. A classificação é um **campo de
primeira classe** com semântica de política:

- a classificação do engajamento é a **mais restritiva** dos seus findings;
- a partir de ``CONFIDENCIAL``, exports exigem redaction (P8);
- ``RESTRITO`` **não** pode sair para provedor de IA externo — só caminho soberano/local
  (reforça P8/soberania).

Domínio puro, determinístico e testável.
"""

from __future__ import annotations

from enum import Enum


class Classification(str, Enum):
    """Nível de sensibilidade, do menos ao mais restrito."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _ORDER[self]

    @property
    def label(self) -> str:
        return _LABELS[self]

    def at_least(self, other: Classification) -> bool:
        return self.rank >= other.rank

    @classmethod
    def from_str(cls, value: str | None, *, default: Classification) -> Classification:
        if not value:
            return default
        try:
            return cls(value.strip().lower())
        except ValueError:
            return default


_ORDER: dict[Classification, int] = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
}

_LABELS: dict[Classification, str] = {
    Classification.PUBLIC: "PÚBLICO",
    Classification.INTERNAL: "INTERNO",
    Classification.CONFIDENTIAL: "CONFIDENCIAL",
    Classification.RESTRICTED: "RESTRITO",
}


def most_restrictive(
    levels: list[Classification], *, default: Classification = Classification.INTERNAL
) -> Classification:
    """A classificação mais restritiva do conjunto (a do engajamento). Vazio ⇒ default."""
    return max(levels, key=lambda c: c.rank) if levels else default


def banner(level: Classification) -> str:
    """Faixa de classificação para cabeçalho/rodapé de relatório."""
    return f"CLASSIFICAÇÃO: {level.label} — distribuição conforme a política do cliente"


def requires_redaction(level: Classification) -> bool:
    """A partir de CONFIDENCIAL, exports/telemetria exigem redaction (P8)."""
    return level.at_least(Classification.CONFIDENTIAL)


def permits_external_provider(level: Classification) -> bool:
    """RESTRITO não pode ir a provedor de IA externo — apenas caminho soberano (P8)."""
    return level.rank < Classification.RESTRICTED.rank
