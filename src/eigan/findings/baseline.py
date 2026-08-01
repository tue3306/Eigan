"""Baseline de risco aceito por engajamento (§13.2).

Um engajamento tem exposições **conhecidas e autorizadas** (aceitas) que não devem gerar
ruído a cada scan. O baseline registra os `fingerprint`s aceitos (com decisão humana) e
particiona os findings de um scan em: **novos** (fora do baseline — o que mudou e merece
atenção), **aceitos** (já no baseline) e **resolvidos** (estavam no baseline e sumiram).
Assim o relatório destaca a mudança em vez de repetir o já aceito. Liga ao diff (pilar 2)
e reusa `Finding.fingerprint` (P6). Toda aceitação exige decisão humana registrada (P9).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .schema import Finding


class InvalidBaselineEntry(ValueError):
    """Entrada de baseline sem decisão humana (decided_by/reference)."""


@dataclass(frozen=True)
class BaselineEntry:
    """Um finding aceito no baseline, com a decisão que o autorizou."""

    fingerprint: str
    decided_by: str
    reference: str
    note: str = ""
    decided_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.fingerprint:
            raise InvalidBaselineEntry("fingerprint é obrigatório")
        if not self.decided_by.strip() or not self.reference.strip():
            raise InvalidBaselineEntry("baseline exige decided_by e reference (P9)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "decided_by": self.decided_by,
            "reference": self.reference,
            "note": self.note,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineEntry:
        raw = data.get("decided_at")
        return cls(
            fingerprint=str(data["fingerprint"]),
            decided_by=str(data.get("decided_by", "")),
            reference=str(data.get("reference", "")),
            note=str(data.get("note", "")),
            decided_at=datetime.fromisoformat(str(raw)) if raw else None,
        )


@dataclass(frozen=True)
class BaselineResult:
    """Partição de um scan em relação ao baseline."""

    new: list[Finding] = field(default_factory=list)
    accepted: list[Finding] = field(default_factory=list)
    resolved_fingerprints: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        """Houve mudança desde o baseline (novos ou resolvidos)?"""
        return bool(self.new or self.resolved_fingerprints)


@dataclass
class Baseline:
    """Conjunto versionado de findings aceitos por engajamento."""

    entries: dict[str, BaselineEntry] = field(default_factory=dict)

    def contains(self, finding: Finding) -> bool:
        return finding.fingerprint in self.entries

    def accept(
        self,
        finding: Finding,
        *,
        decided_by: str,
        reference: str,
        note: str = "",
        decided_at: datetime | None = None,
    ) -> BaselineEntry:
        """Aceita um finding no baseline (decisão humana obrigatória)."""
        entry = BaselineEntry(
            fingerprint=finding.fingerprint,
            decided_by=decided_by,
            reference=reference,
            note=note,
            decided_at=decided_at,
        )
        self.entries[entry.fingerprint] = entry
        return entry

    def partition(self, findings: list[Finding]) -> BaselineResult:
        """Separa os findings em novos/aceitos e detecta os resolvidos (sumiram)."""
        new: list[Finding] = []
        accepted: list[Finding] = []
        seen: set[str] = set()
        for finding in findings:
            seen.add(finding.fingerprint)
            (accepted if finding.fingerprint in self.entries else new).append(finding)
        resolved = sorted(set(self.entries) - seen)
        return BaselineResult(new=new, accepted=accepted, resolved_fingerprints=resolved)

    def digest(self) -> str:
        """SHA-256 do baseline canônico — versão auditável das aceitações vigentes."""
        blob = json.dumps(
            [self.entries[k].to_dict() for k in sorted(self.entries)],
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {"entries": [self.entries[k].to_dict() for k in sorted(self.entries)]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Baseline:
        entries = {}
        for raw in data.get("entries", []):
            entry = BaselineEntry.from_dict(raw)
            entries[entry.fingerprint] = entry
        return cls(entries=entries)
