"""Integração com rastreio de trabalho — propostas de item deduplicadas (§16.3).

A partir dos findings, gera **propostas** de item de trabalho (ticket) — nunca cria nada
automaticamente (P9): a criação irreversível fica com o humano/adaptador. As propostas são
**deduplicadas por classe** (mesmo CWE/título): 50 instâncias de "TLS fraco" viram **uma**
proposta que lista os ativos afetados (liga ao dedup semântico §2.4), evitando abrir 50
tickets do mesmo problema. Campos textuais redigidos (P8).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..ai.sanitize import redact
from ..findings.schema import Finding, Severity


@dataclass(frozen=True)
class WorkItemProposal:
    """Proposta de item de trabalho (revisável) agregando findings de uma classe."""

    title: str
    severity: Severity
    group_key: str  # CWE ou título normalizado — identidade da classe
    affected_assets: list[str] = field(default_factory=list)
    source_tools: list[str] = field(default_factory=list)
    count: int = 0

    @property
    def labels(self) -> list[str]:
        return sorted(
            {f"severity:{self.severity.value}", *(f"tool:{t}" for t in self.source_tools)}
        )


def _group_key(finding: Finding) -> str:
    return (finding.cwe or finding.title).strip().lower()


def propose_work_items(
    findings: list[Finding], *, min_severity: Severity = Severity.MEDIUM
) -> list[WorkItemProposal]:
    """Gera propostas deduplicadas por classe para findings >= ``min_severity``.

    Não cria tickets — devolve propostas para revisão humana (P9). Ordenado por
    severidade (desc) e chave da classe."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.severity.rank >= min_severity.rank:
            groups.setdefault(_group_key(finding), []).append(finding)

    proposals: list[WorkItemProposal] = []
    for key, members in groups.items():
        representative = max(members, key=lambda f: f.severity.rank)
        proposals.append(
            WorkItemProposal(
                title=redact(representative.title),
                severity=representative.severity,
                group_key=key,
                affected_assets=sorted({redact(f.affected_asset) for f in members}),
                source_tools=sorted({f.source_tool for f in members}),
                count=len(members),
            )
        )
    proposals.sort(key=lambda p: (-p.severity.rank, p.group_key))
    return proposals
