"""Constrói o Knowledge Graph de AD a partir da coleta (TIER X.2/X.10).

Converte a coleta autorizada de objetos e relações de AD (usuários, grupos, computadores,
memberships, controle sobre objeto, admin local) em nós e arestas tipadas do Knowledge
Graph. Assim o analisador de attack paths (`find_attack_paths`) opera sobre o grafo — o
mesmo substrato do resto da plataforma (P6). Idempotente e acumulativo; só cria o que a
coleta contém (P1). Os identificadores são fornecidos já qualificados pela coleta (ex.:
``user:alice``, ``group:domainadmins``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from ...graph.graph import KnowledgeGraph
from ...graph.model import EdgeKind, NodeKind

_EVIDENCE = ["ad-collection"]


@dataclass
class AdCollection:
    """Dados coletados de AD (ids já qualificados por tipo)."""

    users: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    computers: list[str] = field(default_factory=list)
    memberships: list[tuple[str, str]] = field(default_factory=list)  # (membro, grupo)
    controls: list[tuple[str, str, str]] = field(default_factory=list)  # (principal, alvo, direito)
    admin_to: list[tuple[str, str]] = field(default_factory=list)  # (principal, computador)


def _label(node_id: str) -> str:
    return node_id.split(":", 1)[-1]


def build_ad_graph(
    collection: AdCollection,
    *,
    graph: KnowledgeGraph | None = None,
    clock: Callable[[], datetime] | None = None,
) -> KnowledgeGraph:
    """Constrói (ou atualiza) o grafo de AD a partir da coleta. Devolve o grafo."""
    g = graph if graph is not None else KnowledgeGraph(clock=clock)

    for uid in collection.users:
        g.add_node(uid, NodeKind.USER, label=_label(uid))
    for gid in collection.groups:
        g.add_node(gid, NodeKind.GROUP, label=_label(gid))
    for cid in collection.computers:
        g.add_node(cid, NodeKind.COMPUTER, label=_label(cid))

    for member, group in collection.memberships:
        g.add_edge(member, group, EdgeKind.MEMBER_OF, evidence=_EVIDENCE)
    for principal, target, right in collection.controls:
        g.add_edge(principal, target, EdgeKind.HAS_CONTROL, evidence=_EVIDENCE, right=right)
    for principal, computer in collection.admin_to:
        g.add_edge(principal, computer, EdgeKind.ADMIN_TO, evidence=_EVIDENCE)

    return g
