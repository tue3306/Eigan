"""Attack Path Analysis de Active Directory (TIER X.2).

Falha antes / passa depois: encontra o caminho de escalonamento (membership + controle +
admin_to) de um principal até Domain Admins, com os direitos corretos; corta ciclos;
enumera múltiplos caminhos (mais curto primeiro); respeita a profundidade máxima; e não
inventa caminho quando não há relação.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from eigan.analysis.ad import find_attack_paths, shortest_attack_path
from eigan.graph.graph import KnowledgeGraph
from eigan.graph.model import EdgeKind, NodeKind


class _Clock:
    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t += timedelta(seconds=1)
        return now


def _ad_graph() -> KnowledgeGraph:
    g = KnowledgeGraph(clock=_Clock())
    g.add_node("user:alice", NodeKind.USER, label="alice")
    g.add_node("group:helpdesk", NodeKind.GROUP, label="Helpdesk")
    g.add_node("group:itadmins", NodeKind.GROUP, label="IT Admins")
    g.add_node("group:domainadmins", NodeKind.GROUP, label="Domain Admins")
    # alice ∈ Helpdesk; Helpdesk tem GenericAll sobre IT Admins; IT Admins ∈ Domain Admins
    g.add_edge("user:alice", "group:helpdesk", EdgeKind.MEMBER_OF, evidence=["ldap"])
    g.add_edge(
        "group:helpdesk",
        "group:itadmins",
        EdgeKind.HAS_CONTROL,
        right="GenericAll",
        evidence=["ldap"],
    )
    g.add_edge("group:itadmins", "group:domainadmins", EdgeKind.MEMBER_OF, evidence=["ldap"])
    return g


def test_finds_escalation_path_to_domain_admins() -> None:
    g = _ad_graph()
    path = shortest_attack_path(g, start="user:alice", target="group:domainadmins")
    assert path is not None
    assert path.length == 3
    assert path.start == "user:alice" and path.target == "group:domainadmins"
    relations = [(s.relation, s.right) for s in path.steps]
    assert relations == [
        ("member_of", ""),
        ("has_control", "GenericAll"),
        ("member_of", ""),
    ]


def test_no_path_when_unrelated() -> None:
    g = _ad_graph()
    g.add_node("user:bob", NodeKind.USER, label="bob")  # sem relações
    assert shortest_attack_path(g, start="user:bob", target="group:domainadmins") is None
    assert find_attack_paths(g, start="user:bob", target="group:domainadmins") == []


def test_cycle_does_not_hang_and_is_pruned() -> None:
    g = KnowledgeGraph(clock=_Clock())
    for n in ("group:a", "group:b", "group:c"):
        g.add_node(n, NodeKind.GROUP)
    g.add_edge("group:a", "group:b", EdgeKind.MEMBER_OF)
    g.add_edge("group:b", "group:c", EdgeKind.MEMBER_OF)
    g.add_edge("group:c", "group:a", EdgeKind.MEMBER_OF)  # ciclo
    path = shortest_attack_path(g, start="group:a", target="group:c")
    assert path is not None and path.length == 2  # a→b→c, sem revisitar


def test_multiple_paths_shortest_first() -> None:
    g = _ad_graph()
    # atalho: alice controla diretamente Domain Admins (WriteDacl)
    g.add_edge(
        "user:alice",
        "group:domainadmins",
        EdgeKind.HAS_CONTROL,
        right="WriteDacl",
        evidence=["ldap"],
    )
    paths = find_attack_paths(g, start="user:alice", target="group:domainadmins")
    assert len(paths) == 2
    assert paths[0].length == 1  # o atalho direto vem primeiro
    assert paths[0].steps[0].right == "WriteDacl"


def test_max_depth_bounds_search() -> None:
    g = _ad_graph()
    # com profundidade 2, o caminho de 3 passos não é alcançado
    assert find_attack_paths(g, start="user:alice", target="group:domainadmins", max_depth=2) == []
    assert find_attack_paths(g, start="user:alice", target="group:domainadmins", max_depth=3) != []
