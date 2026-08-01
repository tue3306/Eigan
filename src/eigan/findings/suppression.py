"""Marcação de finding e supressão versionada (§13.1).

A causa nº 1 de abandono de ferramenta de segurança é o mesmo falso-positivo
re-alertando a cada scan. O analista marca um finding como **falso-positivo** ou
**risco aceito**, e a marcação vira uma **regra de supressão versionada** (por
ativo/classe/padrão) aplicada a scans futuros.

Invariantes (P2/P9):

- **Nunca some:** um finding suprimido **não desaparece** — ele é marcado como
  "suprimido por decisão em <referência>", preservando rastreabilidade (P2).
- **Nunca sem humano:** toda regra exige ``decided_by`` e uma ``reference`` (decisão
  humana registrada — P9); e ao menos um matcher (não se suprime tudo às cegas).
- **Reversível e versionada:** o conjunto é dado (YAML/dict) com ``digest`` — remover
  uma regra reverte a supressão; a marcação é auditável.

Reusa `FindingStatus` (FALSE_POSITIVE / ACCEPTED_RISK) como veredito — não inventa um
enum paralelo (P6).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .schema import Finding, FindingStatus

_SUPPRESSING = {FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK}


class InvalidSuppressionRule(ValueError):
    """Regra de supressão malformada (sem decisão humana ou sem matcher)."""


@dataclass(frozen=True)
class SuppressionRule:
    """Regra que suprime findings equivalentes com base numa decisão humana."""

    rule_id: str
    verdict: FindingStatus  # FALSE_POSITIVE ou ACCEPTED_RISK
    decided_by: str  # quem decidiu (P9)
    reference: str  # referência da decisão (ticket/commit/ata) — rastreabilidade
    reason: str = ""
    asset: str | None = None  # glob do ativo afetado (fnmatch)
    cwe: str | None = None  # ex.: 'CWE-89'
    fingerprint: str | None = None  # identidade exata do finding
    title_contains: str | None = None  # substring do título (case-insensitive)
    decided_at: datetime | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.verdict not in _SUPPRESSING:
            raise InvalidSuppressionRule("verdict deve ser FALSE_POSITIVE ou ACCEPTED_RISK")
        if not self.decided_by.strip() or not self.reference.strip():
            raise InvalidSuppressionRule("supressão exige decided_by e reference (P9)")
        if not any((self.asset, self.cwe, self.fingerprint, self.title_contains)):
            raise InvalidSuppressionRule("ao menos um matcher é obrigatório (não suprimir tudo)")

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now > self.expires_at

    def matches(self, finding: Finding, *, now: datetime) -> bool:
        """A regra casa este finding? Todos os matchers definidos precisam casar (AND)."""
        if self.is_expired(now):
            return False
        if self.asset is not None and not fnmatch.fnmatch(
            finding.affected_asset.lower(), self.asset.lower()
        ):
            return False
        if self.cwe is not None and (finding.cwe or "").upper() != self.cwe.upper():
            return False
        if self.fingerprint is not None and finding.fingerprint != self.fingerprint:
            return False
        if (
            self.title_contains is not None
            and self.title_contains.lower() not in finding.title.lower()
        ):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule_id": self.rule_id,
            "verdict": self.verdict.value,
            "decided_by": self.decided_by,
            "reference": self.reference,
            "reason": self.reason,
            "asset": self.asset,
            "cwe": self.cwe,
            "fingerprint": self.fingerprint,
            "title_contains": self.title_contains,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuppressionRule:
        def _dt(key: str) -> datetime | None:
            raw = data.get(key)
            return datetime.fromisoformat(str(raw)) if raw else None

        return cls(
            rule_id=str(data["rule_id"]),
            verdict=FindingStatus(str(data["verdict"])),
            decided_by=str(data.get("decided_by", "")),
            reference=str(data.get("reference", "")),
            reason=str(data.get("reason", "")),
            asset=data.get("asset"),
            cwe=data.get("cwe"),
            fingerprint=data.get("fingerprint"),
            title_contains=data.get("title_contains"),
            decided_at=_dt("decided_at"),
            expires_at=_dt("expires_at"),
        )


@dataclass(frozen=True)
class SuppressionOutcome:
    """Resultado de aplicar o conjunto a um finding: suprimido ou não, e por qual regra."""

    finding: Finding
    rule: SuppressionRule | None

    @property
    def suppressed(self) -> bool:
        return self.rule is not None

    @property
    def note(self) -> str:
        if self.rule is None:
            return ""
        return f"suprimido por decisão em {self.rule.reference}"

    def marked(self) -> Finding:
        """Cópia do finding com o status do veredito — **sem** remover o finding.

        O original é preservado; a marcação carrega a rastreabilidade da decisão."""
        if self.rule is None:
            return self.finding
        return self.finding.model_copy(update={"status": self.rule.verdict})


@dataclass
class SuppressionSet:
    """Conjunto versionado de regras de supressão."""

    rules: list[SuppressionRule] = field(default_factory=list)

    def find_rule(self, finding: Finding, *, now: datetime) -> SuppressionRule | None:
        """Primeira regra (não expirada) que casa o finding, ou None."""
        for rule in self.rules:
            if rule.matches(finding, now=now):
                return rule
        return None

    def apply(self, findings: list[Finding], *, now: datetime) -> list[SuppressionOutcome]:
        """Aplica o conjunto a uma lista, **preservando** todos os findings (nenhum é
        removido); os suprimidos apenas ganham a regra/veredito associados."""
        return [SuppressionOutcome(f, self.find_rule(f, now=now)) for f in findings]

    def digest(self) -> str:
        """SHA-256 do conjunto canônico — versão auditável das regras vigentes."""
        blob = json.dumps(
            [r.to_dict() for r in self.rules],
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [r.to_dict() for r in self.rules]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuppressionSet:
        return cls(rules=[SuppressionRule.from_dict(r) for r in data.get("rules", [])])
