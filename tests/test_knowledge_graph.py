"""Knowledge Graph core (Parte 2 do roadmap): nós/arestas, idempotência, consulta, diff.

Falha antes / passa depois: inserção idempotente que mescla; conflito de tipo; aresta
exige nós existentes; consulta por tipo/atributo/vizinho; diff scan-a-scan; round-trip
de serialização determinístico.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from eigan.graph import (
    EdgeKind,
    GraphConflict,
    KnowledgeGraph,
    NodeKind,
)


class _Clock:
    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t += timedelta(seconds=1)
        return now


def _sample() -> KnowledgeGraph:
    g = KnowledgeGraph(clock=_Clock())
    g.add_node("host:10.0.0.1", NodeKind.HOST, label="dc01")
    g.add_node("svc:smb", NodeKind.SERVICE, label="SMB 445")
    g.add_node("tech:iis", NodeKind.TECHNOLOGY, label="IIS", product="iis")
    g.add_node("vuln:smb-signing", NodeKind.VULNERABILITY, label="SMB Signing Disabled")
    g.add_edge("svc:smb", "host:10.0.0.1", EdgeKind.HOSTED_ON, evidence=["nmap"])
    g.add_edge("host:10.0.0.1", "tech:iis", EdgeKind.RUNS, evidence=["httpx"])
    g.add_edge("host:10.0.0.1", "vuln:smb-signing", EdgeKind.AFFECTED_BY, evidence=["nuclei"])
    return g


def test_add_node_is_idempotent_and_merges() -> None:
    g = KnowledgeGraph(clock=_Clock())
    n1 = g.add_node("h1", NodeKind.HOST, label="a", os="linux")
    n2 = g.add_node("h1", NodeKind.HOST, role="dc")  # mesmo id → mescla
    assert n1 is n2
    assert len(g) == 1
    assert n2.attributes == {"os": "linux", "role": "dc"}
    assert n2.last_seen > n2.first_seen  # last_seen avançou


def test_kind_conflict_is_rejected() -> None:
    g = KnowledgeGraph(clock=_Clock())
    g.add_node("x", NodeKind.HOST)
    with pytest.raises(GraphConflict):
        g.add_node("x", NodeKind.SERVICE)  # mesmo id, tipo diferente


def test_edge_requires_existing_nodes() -> None:
    g = KnowledgeGraph(clock=_Clock())
    g.add_node("a", NodeKind.HOST)
    with pytest.raises(KeyError):
        g.add_edge("a", "b", EdgeKind.CONNECTED_TO)  # 'b' não existe


def test_edge_merges_evidence() -> None:
    g = _sample()
    e = g.add_edge("svc:smb", "host:10.0.0.1", EdgeKind.HOSTED_ON, evidence=["naabu"])
    assert e.evidence == ["naabu", "nmap"]  # evidência acumulada e ordenada
    assert g.edge_count == 3  # não criou aresta nova


def test_query_by_kind_neighbors_and_attribute() -> None:
    g = _sample()
    assert [n.node_id for n in g.nodes_by_kind(NodeKind.VULNERABILITY)] == ["vuln:smb-signing"]
    # vizinhos de saída do host
    outs = {n.node_id for n in g.neighbors("host:10.0.0.1", direction="out")}
    assert outs == {"tech:iis", "vuln:smb-signing"}
    # vizinho de entrada (o serviço aponta para o host)
    ins = {n.node_id for n in g.neighbors("host:10.0.0.1", direction="in")}
    assert ins == {"svc:smb"}
    # filtro por atributo
    assert [n.node_id for n in g.find(kind=NodeKind.TECHNOLOGY, product="iis")] == ["tech:iis"]


def test_diff_reports_added_and_removed() -> None:
    prev = _sample()
    cur = _sample()
    cur.add_node("host:10.0.0.2", NodeKind.HOST, label="novo")
    cur.add_edge("host:10.0.0.2", "tech:iis", EdgeKind.RUNS, evidence=["httpx"])
    diff = cur.diff(prev)
    assert diff.added_nodes == ["host:10.0.0.2"]
    assert ("host:10.0.0.2", "runs", "tech:iis") in diff.added_edges
    assert diff.removed_nodes == []
    assert diff.empty is False
    assert cur.diff(cur).empty is True  # idêntico ⇒ diff vazio


def test_serialization_round_trip_is_deterministic() -> None:
    g = _sample()
    data = g.to_dict()
    restored = KnowledgeGraph.from_dict(data)
    assert restored.to_dict() == data  # round-trip estável
    assert len(restored) == len(g)
    assert restored.edge_count == g.edge_count
    assert restored.node("host:10.0.0.1").label == "dc01"
