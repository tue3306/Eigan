"""Correlation Engine sobre o grafo (Parte 1): cadeias, confiança e risco contextual.

Falha antes / passa depois: correlaciona exposições de um ativo numa cadeia ordenada por
severidade, com confiança crescente na diversidade de ferramentas, risco contextual e
narrativa determinística baseada só em evidência; chains ordenadas por risco.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from eigan.findings.schema import Finding, Severity
from eigan.graph import build_graph
from eigan.graph.correlation import compute_confidence, correlate_attack_chains


class _Clock:
    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t += timedelta(seconds=1)
        return now


def _f(**kw) -> Finding:
    base = dict(
        title="v", severity=Severity.MEDIUM, affected_asset="10.0.0.1", source_tool="nuclei"
    )
    base.update(kw)
    return Finding(**base)


def test_confidence_grows_with_tool_diversity() -> None:
    assert compute_confidence(1, 1) == 25  # uma ferramenta, uma evidência
    assert compute_confidence(2, 2) == 45  # duas ferramentas independentes
    assert compute_confidence(3, 3) == 65
    # corroboração extra da mesma ferramenta soma menos que diversidade
    assert compute_confidence(1, 3) == 35
    assert compute_confidence(5, 20) <= 100  # nunca passa de 100


def test_chain_orders_steps_by_severity_and_computes_risk() -> None:
    findings = [
        _f(title="porta 445 aberta", severity=Severity.LOW, source_tool="nmap"),
        _f(title="SMB signing disabled", severity=Severity.HIGH, source_tool="nuclei"),
    ]
    chains = correlate_attack_chains(build_graph(findings, clock=_Clock()))
    assert len(chains) == 1
    chain = chains[0]
    assert chain.is_chain is True  # ≥2 exposições correlacionadas
    # ordenado da menor para a maior severidade
    assert [s.severity for s in chain.steps] == ["low", "high"]
    # duas ferramentas independentes → confiança 45
    assert chain.confidence == 45
    assert 0 < chain.risk_score <= 100
    assert "10.0.0.1" in chain.narrative
    assert "%" in chain.narrative  # confiança aparece na narrativa (transparência)


def test_references_from_graph_appear_in_step() -> None:
    findings = [_f(cwe="CWE-89", owasp="A03:2021", attack_technique="T1190")]
    chain = correlate_attack_chains(build_graph(findings, clock=_Clock()))[0]
    refs = chain.steps[0].references
    assert "CWE-89" in refs and "A03:2021" in refs and "T1190" in refs


def test_single_finding_is_not_a_chain_but_still_scored() -> None:
    chain = correlate_attack_chains(build_graph([_f(severity=Severity.CRITICAL)], clock=_Clock()))[
        0
    ]
    assert chain.is_chain is False
    # crítico pontua alto mesmo sozinho, mas a baixa corroboração (1 fonte) modula o
    # risco para baixo — risco contextual, não CVSS cru (honesto).
    assert chain.risk_score == 70


def test_chains_sorted_by_risk_desc() -> None:
    findings = [
        _f(affected_asset="10.0.0.1", severity=Severity.LOW),
        _f(affected_asset="10.0.0.2", severity=Severity.CRITICAL),
    ]
    chains = correlate_attack_chains(build_graph(findings, clock=_Clock()))
    assert [c.asset for c in chains] == ["10.0.0.2", "10.0.0.1"]  # maior risco primeiro


def test_nothing_invented_without_evidence() -> None:
    # ativo sem finding não gera cadeia
    chains = correlate_attack_chains(build_graph([], clock=_Clock()))
    assert chains == []
