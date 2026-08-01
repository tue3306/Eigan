"""Consultas inteligentes e Impact Analysis sobre o grafo (Parte 2).

Falha antes / passa depois: Impact Analysis (ativos afetados por uma CWE), histórico
(ativos novos desde um instante), prevalência de referências e ranking de risco — tudo
navegando o grafo, sem inventar nada.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from eigan.findings.schema import Finding, Severity
from eigan.graph import build_graph
from eigan.graph.query import (
    assets_added_since,
    assets_affected_by,
    reference_prevalence,
    riskiest_assets,
)


class _Clock:
    def __init__(self, start: datetime | None = None) -> None:
        self._t = start or datetime(2026, 1, 1, tzinfo=timezone.utc)

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


def test_impact_analysis_finds_affected_assets() -> None:
    findings = [
        _f(affected_asset="10.0.0.1", cwe="CWE-89"),
        _f(affected_asset="10.0.0.2", cwe="CWE-89"),
        _f(affected_asset="10.0.0.3", cwe="CWE-79"),  # CWE diferente
    ]
    g = build_graph(findings, clock=_Clock())
    affected = [n.node_id for n in assets_affected_by(g, "cwe:CWE-89")]
    assert affected == ["asset:10.0.0.1", "asset:10.0.0.2"]  # só os afetados pela CWE-89
    assert assets_affected_by(g, "cwe:CWE-9999") == []  # referência inexistente


def test_assets_added_since_history() -> None:
    clock = _Clock()
    g = build_graph([_f(affected_asset="10.0.0.1")], graph=None, clock=clock)
    cutoff = clock()  # instante entre os dois scans
    build_graph([_f(affected_asset="10.0.0.9")], graph=g)  # ativo novo, first_seen > cutoff
    added = [n.node_id for n in assets_added_since(g, cutoff)]
    assert added == ["asset:10.0.0.9"]  # só o ativo novo


def test_reference_prevalence_orders_by_count() -> None:
    findings = [
        _f(affected_asset="a", cwe="CWE-89"),
        _f(affected_asset="b", cwe="CWE-89"),
        _f(affected_asset="c", cwe="CWE-79"),
    ]
    g = build_graph(findings, clock=_Clock())
    prevalence = reference_prevalence(g)
    assert prevalence[0] == ("CWE-89", 2)  # a mais presente primeiro
    assert ("CWE-79", 1) in prevalence


def test_riskiest_assets_ranked_and_top_n() -> None:
    findings = [
        _f(affected_asset="10.0.0.1", severity=Severity.LOW),
        _f(affected_asset="10.0.0.2", severity=Severity.CRITICAL),
        _f(affected_asset="10.0.0.3", severity=Severity.MEDIUM),
    ]
    g = build_graph(findings, clock=_Clock())
    top1 = riskiest_assets(g, top=1)
    assert len(top1) == 1
    assert top1[0].asset == "10.0.0.2"  # o de maior risco
    assert len(riskiest_assets(g)) == 3  # sem top → todos
