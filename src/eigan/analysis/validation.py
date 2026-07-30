"""Validação de findings — confiança EXPLÍCITA e grounded (§16 anti-falso-positivo).

A política de validação do EIGAN (ADR-0027) exige: toda finding com **nível de confiança explícito**, e
findings não validadas **marcadas como tais** — nunca empurrar falso-positivo como
fato. Esta camada é a etapa de *Validation* do §8, separada e testável.

Regra de ouro (§2/§16): a confiança só **sobe** com sinal real; nunca é fabricada
nem inflada, e a validação **não rebaixa** o que a ferramenta afirmou.

* **Validação ativa** — a vuln foi provada por PoC não-destrutiva (sqlmap → SQLi,
  dalfox → XSS; nomes verificados nos runners) → ``CONFIRMED``.
* **Corroboração** — ≥ 2 fontes independentes relataram a mesma vuln (mesmo
  ``fingerprint``, via ``dedup``) → ao menos ``FIRM``.
* **Fonte única, sem prova** → preserva a confiança reportada pela ferramenta.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..findings.schema import Confidence, Finding

# Ferramentas que VALIDAM a vuln empiricamente (PoC não-destrutiva). Verificado nos
# runners: plugins/red/sqlmap/runner.py (name="sqlmap"), .../dalfox (name="dalfox").
_ACTIVE_VALIDATORS = frozenset({"sqlmap", "dalfox"})

_RANK: dict[Confidence, int] = {
    Confidence.UNVERIFIED: 0,
    Confidence.TENTATIVE: 1,
    Confidence.FIRM: 2,
    Confidence.CONFIRMED: 3,
}


@dataclass(frozen=True)
class Validation:
    """Veredito de validação de uma finding."""

    confidence: Confidence
    validated: bool
    rationale: str


@dataclass
class ValidationSummary:
    """Agregado de validação de um conjunto de findings (para dashboard/relatório)."""

    total: int = 0
    validated: int = 0
    by_confidence: dict[str, int] = field(default_factory=dict)

    def _count(self, v: Validation) -> None:
        self.total += 1
        if v.validated:
            self.validated += 1
        self.by_confidence[v.confidence.value] = self.by_confidence.get(v.confidence.value, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "validated": self.validated,
            "by_confidence": dict(self.by_confidence),
        }


class Validator:
    """Atribui confiança explícita e grounded (§16). Só sobe com prova; nunca rebaixa."""

    def assess(self, finding: Finding) -> Validation:
        tool = finding.source_tool.lower()
        sources = {s for s in ([finding.source_tool, *finding.correlated_sources]) if s}
        if tool in _ACTIVE_VALIDATORS:
            return Validation(
                Confidence.CONFIRMED,
                True,
                f"validado ativamente por {finding.source_tool} (PoC não-destrutiva)",
            )
        if len(sources) >= 2:
            # sobe para FIRM só se ainda não está em FIRM/CONFIRMED (nunca rebaixa).
            upgraded = (
                finding.confidence
                if _RANK[finding.confidence] >= _RANK[Confidence.FIRM]
                else Confidence.FIRM
            )
            return Validation(
                upgraded,
                True,
                f"corroborado por {len(sources)} fontes: {', '.join(sorted(sources))}",
            )
        return Validation(
            finding.confidence, False, "fonte única, sem corroboração — confiança preservada"
        )

    def apply(self, findings: list[Finding]) -> ValidationSummary:
        """Atribui a confiança validada A CADA finding (mutação) e devolve o resumo."""
        summary = ValidationSummary()
        for finding in findings:
            verdict = self.assess(finding)
            finding.confidence = verdict.confidence
            summary._count(verdict)
        return summary

    def summarize(self, findings: list[Finding]) -> ValidationSummary:
        """Resumo somente-leitura (não muta) — para exibir a partir do que já está salvo."""
        summary = ValidationSummary()
        for finding in findings:
            summary._count(self.assess(finding))
        return summary
