"""Triagem barata → aprofundamento caro (§2.5): modelo caro só onde agrega valor.

A triagem determinística (por severidade, zero token) decide DEEP (narrativa por
IA) ou BRIEF (enriquecimento determinístico). Nunca descarta; alto/crítico sempre
DEEP; configurável por ``EIGAN_TRIAGE_MIN_SEVERITY``.
"""

from __future__ import annotations

from pathlib import Path

from eigan.ai.provider import Enricher, Explanation
from eigan.findings.schema import Finding, Severity
from eigan.knowledge.loader import KnowledgeBase

_KB = Path(__file__).resolve().parents[1] / "knowledge" / "skills"


class _CountingProvider:
    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def explain(self, finding: Finding, context: str) -> Explanation:
        self.calls += 1
        return Explanation(text="ai", remediation="r", ai_generated=True)


def _f(sev: Severity, asset: str, cwe: str) -> Finding:
    return Finding(title="T", severity=sev, affected_asset=asset, source_tool="t", cwe=cwe)


def test_triage_sends_only_relevant_to_ai(monkeypatch) -> None:
    monkeypatch.delenv("EIGAN_TRIAGE_MIN_SEVERITY", raising=False)  # default: low
    p = _CountingProvider()
    enr = Enricher(KnowledgeBase(_KB), provider=p)
    findings = [
        _f(Severity.INFO, "a", cwe="CWE-1"),  # < low → BRIEF (determinístico)
        _f(Severity.HIGH, "b", cwe="CWE-2"),  # >= low → DEEP (IA)
    ]
    exps = enr.explain_all(findings)
    assert p.calls == 1  # só a classe HIGH foi ao modelo caro
    assert exps[0].ai_generated is False  # INFO: determinístico (auditável)
    assert exps[1].ai_generated is True  # HIGH: IA


def test_triage_high_always_deep_even_with_aggressive_threshold(monkeypatch) -> None:
    # Mesmo pedindo 'critical', o teto de segurança mantém HIGH em análise profunda.
    monkeypatch.setenv("EIGAN_TRIAGE_MIN_SEVERITY", "critical")
    p = _CountingProvider()
    enr = Enricher(KnowledgeBase(_KB), provider=p)
    exps = enr.explain_all([_f(Severity.HIGH, "b", cwe="CWE-9")])
    assert p.calls == 1 and exps[0].ai_generated is True


def test_triage_info_threshold_sends_everything_to_ai(monkeypatch) -> None:
    monkeypatch.setenv("EIGAN_TRIAGE_MIN_SEVERITY", "info")  # tudo no modelo caro
    p = _CountingProvider()
    enr = Enricher(KnowledgeBase(_KB), provider=p)
    enr.explain_all([_f(Severity.INFO, "a", cwe="CWE-3")])
    assert p.calls == 1  # até INFO vai à IA


def test_triage_never_discards_only_deprioritizes(monkeypatch) -> None:
    monkeypatch.setenv("EIGAN_TRIAGE_MIN_SEVERITY", "high")  # economia agressiva
    enr = Enricher(KnowledgeBase(_KB), provider=_CountingProvider())
    exps = enr.explain_all([_f(Severity.LOW, "a", cwe="CWE-4")])
    assert len(exps) == 1 and exps[0].text  # explicação presente (nada descartado)
    assert exps[0].ai_generated is False  # desprioritizada (determinística), auditável
