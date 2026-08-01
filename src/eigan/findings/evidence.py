"""Cadeia de custódia da evidência (§21.1).

Um achado só é defensável se a evidência que o sustenta for **íntegra**. Ao coletar, a
evidência é **hasheada e datada**; o hash entra na trilha de auditoria (§18.3) e permite
detectar alteração posterior do artefato armazenado. Determinístico (relógio/data
injetados) e sem dependência externa.

Honestidade (P1/P2): o selo garante que a evidência **armazenada** não foi alterada após a
coleta. A evidência é armazenada já redigida (P8/§11.2), então o selo é do artefato
redigido — é o que se guarda e o que se precisa provar íntegro. Não afirmamos poder
reconstruir o original em claro (que não é retido).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class EvidenceRecord:
    """Selo de custódia: identidade criptográfica e temporal da evidência coletada."""

    sha256: str
    collected_at: str  # ISO 8601
    source: str  # ferramenta/comando que produziu a evidência
    size: int  # bytes do artefato selado

    def to_dict(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "collected_at": self.collected_at,
            "source": self.source,
            "size": self.size,
        }


def _as_bytes(content: str | bytes) -> bytes:
    return content if isinstance(content, bytes) else content.encode("utf-8")


def seal_evidence(content: str | bytes, *, source: str, at: datetime) -> EvidenceRecord:
    """Sela a evidência: calcula o SHA-256 e carimba a data de coleta."""
    raw = _as_bytes(content)
    return EvidenceRecord(
        sha256=hashlib.sha256(raw).hexdigest(),
        collected_at=at.isoformat(),
        source=source,
        size=len(raw),
    )


def verify_evidence(record: EvidenceRecord, content: str | bytes) -> bool:
    """Confere se ``content`` corresponde ao selo (evidência não foi alterada)."""
    raw = _as_bytes(content)
    return len(raw) == record.size and hashlib.sha256(raw).hexdigest() == record.sha256
