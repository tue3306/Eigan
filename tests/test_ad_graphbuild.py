"""Construção do grafo de AD a partir da coleta (TIER X.2/X.10).

Falha antes / passa depois: a coleta vira nós/arestas tipadas e o attack-path opera sobre
o grafo construído; aresta para nó inexistente é recusada; idempotente/acumulativo.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from eigan.analysis.ad import shortest_attack_path
from eigan.analysis.ad.graphbuild import AdCollection, build_ad_graph
from eigan.graph.model import EdgeKind, NodeKind


class _Clock:
    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t += timedelta(seconds=1)
        return now


def _collection() -> AdCollection:
    return AdCollection(
        users=["user:alice"],
        groups=["group:helpdesk", "group:domainadmins"],
        computers=["computer:ws01"],
        memberships=[("user:alice", "group:helpdesk"), ("group:helpdesk", "group:domainadmins")],
        controls=[("user:alice", "computer:ws01", "GenericAll")],
        admin_to=[("user:alice", "computer:ws01")],
    )


def test_builds_typed_nodes_and_edges() -> None:
    g = build_ad_graph(_collection(), clock=_Clock())
    assert g.node("user:alice").kind is NodeKind.USER
    assert g.node("group:domainadmins").kind is NodeKind.GROUP
    assert g.node("computer:ws01").kind is NodeKind.COMPUTER
    assert g.has_edge("user:alice", EdgeKind.MEMBER_OF, "group:helpdesk")
    assert g.has_edge("user:alice", EdgeKind.HAS_CONTROL, "computer:ws01")
    assert g.has_edge("user:alice", EdgeKind.ADMIN_TO, "computer:ws01")


def test_attack_path_runs_on_built_graph() -> None:
    g = build_ad_graph(_collection(), clock=_Clock())
    path = shortest_attack_path(g, start="user:alice", target="group:domainadmins")
    assert path is not None
    assert path.length == 2  # alice → helpdesk → domainadmins
    assert [s.relation for s in path.steps] == ["member_of", "member_of"]


def test_edge_to_unknown_node_is_rejected() -> None:
    bad = AdCollection(users=["user:a"], memberships=[("user:a", "group:ghost")])
    with pytest.raises(KeyError):
        build_ad_graph(bad, clock=_Clock())  # 'group:ghost' não foi declarado


def test_build_is_idempotent_and_accumulative() -> None:
    clock = _Clock()
    g = build_ad_graph(_collection(), clock=clock)
    n = len(g)
    build_ad_graph(_collection(), graph=g)  # reexecutar não duplica
    assert len(g) == n
    build_ad_graph(AdCollection(users=["user:bob"]), graph=g)  # acumula
    assert g.node("user:bob") is not None
