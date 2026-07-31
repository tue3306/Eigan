"""Dedup semântica antes da IA (§2.4): analisar 1 representante por classe.

O custo de análise cresce com o número de CLASSES de finding, não com o número
bruto de instâncias — 50 'TLS fraco' em ativos diferentes viram 1 chamada.
"""

from __future__ import annotations

from pathlib import Path

from eigan.ai.provider import Enricher, Explanation
from eigan.findings.schema import Finding, Severity
from eigan.knowledge.loader import KnowledgeBase

_KB = Path(__file__).resolve().parents[1] / "knowledge" / "skills"


class _CountingProvider:
    """Provedor fake que conta quantas análises reais foram feitas."""

    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def explain(self, finding: Finding, context: str) -> Explanation:
        self.calls += 1
        return Explanation(text=f"exp:{finding.affected_asset}", remediation="r", ai_generated=True)


def _f(cwe: str | None, asset: str, title: str = "T") -> Finding:
    return Finding(
        title=title, severity=Severity.HIGH, affected_asset=asset, source_tool="t", cwe=cwe
    )


def test_explain_all_dedups_by_cwe_class() -> None:
    provider = _CountingProvider()
    enr = Enricher(KnowledgeBase(_KB), provider=provider)
    findings = [
        _f("CWE-327", "host-a"),
        _f("CWE-327", "host-b"),  # mesma classe → propaga
        _f("CWE-327", "host-c"),
        _f("CWE-89", "host-d"),  # outra classe
    ]
    exps = enr.explain_all(findings)
    assert provider.calls == 2  # 2 CLASSES, não 4 instâncias
    assert exps[0] is exps[1] is exps[2]  # mesma explicação propagada ao grupo
    assert exps[3] is not exps[0]
    assert len(exps) == len(findings)  # uma por finding, na ordem de entrada


def test_explain_all_groups_by_title_without_cwe() -> None:
    provider = _CountingProvider()
    enr = Enricher(KnowledgeBase(_KB), provider=provider)
    findings = [
        _f(None, "a", title="TLS fraco"),
        _f(None, "b", title="TLS fraco"),  # mesmo título → mesma classe
        _f(None, "c", title="Header ausente"),
    ]
    enr.explain_all(findings)
    assert provider.calls == 2


def test_explain_all_empty() -> None:
    enr = Enricher(KnowledgeBase(_KB), provider=_CountingProvider())
    assert enr.explain_all([]) == []
