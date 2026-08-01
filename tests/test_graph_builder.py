"""Construção do Knowledge Graph a partir de findings (Parte 2 do roadmap).

Falha antes / passa depois: findings viram nós de ativo/finding com arestas
AFFECTED_BY e REFERENCES (CWE/OWASP/MITRE); só se cria o que há evidência; a construção
é idempotente/acumulativa e a evidência (ferramenta) acompanha a aresta.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from eigan.findings.schema import Finding, Severity
from eigan.graph import EdgeKind, NodeKind, build_graph
from eigan.graph.graph import KnowledgeGraph


class _Clock:
    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t += timedelta(seconds=1)
        return now


def _f(**kw) -> Finding:
    base = dict(
        title="SQLi", severity=Severity.HIGH, affected_asset="10.0.0.1", source_tool="nuclei"
    )
    base.update(kw)
    return Finding(**base)


def test_builds_asset_finding_and_reference_nodes() -> None:
    g = build_graph([_f(cwe="CWE-89", owasp="A03:2021", attack_technique="T1190")], clock=_Clock())
    assert g.node("asset:10.0.0.1").kind is NodeKind.HOST
    assert len(g.nodes_by_kind(NodeKind.FINDING)) == 1
    assert len(g.nodes_by_kind(NodeKind.CWE)) == 1
    assert len(g.nodes_by_kind(NodeKind.OWASP)) == 1
    assert len(g.nodes_by_kind(NodeKind.MITRE_TECHNIQUE)) == 1

    finding = g.nodes_by_kind(NodeKind.FINDING)[0]
    # o ativo é afetado pelo finding; o finding referencia a CWE
    assert g.has_edge("asset:10.0.0.1", EdgeKind.AFFECTED_BY, finding.node_id)
    assert g.has_edge(finding.node_id, EdgeKind.REFERENCES, "cwe:CWE-89")


def test_only_creates_what_evidence_supports() -> None:
    # sem CWE/OWASP/MITRE, nenhum nó de referência é inventado (P1)
    g = build_graph([_f()], clock=_Clock())
    assert g.nodes_by_kind(NodeKind.CWE) == []
    assert g.nodes_by_kind(NodeKind.OWASP) == []
    assert g.nodes_by_kind(NodeKind.MITRE_TECHNIQUE) == []


def test_evidence_tool_accompanies_edge() -> None:
    g = build_graph([_f(source_tool="sqlmap", cwe="CWE-89")], clock=_Clock())
    finding = g.nodes_by_kind(NodeKind.FINDING)[0]
    edge = next(e for e in g.edges() if e.dst == finding.node_id)
    assert edge.evidence == ["sqlmap"]


def test_build_is_idempotent_and_accumulative() -> None:
    clock = _Clock()
    g = KnowledgeGraph(clock=clock)
    build_graph([_f(cwe="CWE-89")], graph=g)
    n_after_first = len(g)
    # reexecutar com o MESMO finding não duplica nós
    build_graph([_f(cwe="CWE-89")], graph=g)
    assert len(g) == n_after_first
    # um finding NOVO em outro ativo acumula
    build_graph([_f(affected_asset="10.0.0.2", cwe="CWE-79")], graph=g)
    assert g.node("asset:10.0.0.2") is not None
    assert len(g.nodes_by_kind(NodeKind.CWE)) == 2


def test_multiple_tools_on_same_asset_share_node() -> None:
    g = build_graph(
        [
            _f(affected_asset="10.0.0.1", source_tool="nmap", title="porta 445"),
            _f(affected_asset="10.0.0.1", source_tool="nuclei", title="SMB signing"),
        ],
        clock=_Clock(),
    )
    # um único nó de ativo, dois findings ligados a ele
    assert len(g.nodes_by_kind(NodeKind.HOST)) == 1
    affected = g.neighbors("asset:10.0.0.1", kind=EdgeKind.AFFECTED_BY, direction="out")
    assert len(affected) == 2
