"""Knowledge Graph persistente: inserção idempotente, consulta, diff e serialização.

Um modelo vivo da infraestrutura: cada execução **atualiza** o conhecimento existente
(inserção idempotente por identidade), nunca apaga sem justificativa. O ``diff`` entre
dois grafos alimenta o histórico (novos/removidos ativos, vulnerabilidades, mudança de
superfície). As consultas navegam o grafo (nós por tipo, vizinhos, filtros de atributo),
respondendo perguntas que um relatório de findings isolados não responde.

Determinístico: toda saída é ordenada; o relógio de ``first_seen``/``last_seen`` é
injetável para testes reproduzíveis (§21.3).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .model import Edge, EdgeKind, Node, NodeKind


class GraphConflict(Exception):
    """Um ``node_id`` foi reinserido com um ``kind`` diferente do já registrado."""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class GraphDiff:
    """Diferença entre dois grafos (histórico scan-a-scan)."""

    added_nodes: list[str] = field(default_factory=list)
    removed_nodes: list[str] = field(default_factory=list)
    added_edges: list[tuple[str, str, str]] = field(default_factory=list)
    removed_edges: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (
            self.added_nodes or self.removed_nodes or self.added_edges or self.removed_edges
        )


class KnowledgeGraph:
    """Grafo de conhecimento com inserção idempotente, consulta, diff e serialização."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or _now_utc
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}

    # ── inserção idempotente ────────────────────────────────────────────────
    def add_node(self, node_id: str, kind: NodeKind, *, label: str = "", **attributes: str) -> Node:
        """Insere ou atualiza um nó. Reinserir mescla atributos e atualiza ``last_seen``;
        mudar o ``kind`` de um id existente é conflito (`GraphConflict`)."""
        now = self._clock()
        existing = self._nodes.get(node_id)
        if existing is None:
            node = Node(
                node_id=node_id,
                kind=kind,
                label=label,
                attributes=dict(attributes),
                first_seen=now,
                last_seen=now,
            )
            self._nodes[node_id] = node
            return node
        if existing.kind != kind:
            raise GraphConflict(
                f"nó '{node_id}' já existe como {existing.kind.value}, não {kind.value}"
            )
        if label:
            existing.label = label
        existing.attributes.update(attributes)
        existing.last_seen = now
        return existing

    def add_edge(
        self,
        src: str,
        dst: str,
        kind: EdgeKind,
        *,
        evidence: list[str] | None = None,
        **attributes: str,
    ) -> Edge:
        """Insere ou atualiza uma aresta. Ambos os nós precisam existir (nenhuma relação
        para nó fantasma). Reinserir mescla evidência/atributos e atualiza ``last_seen``."""
        for endpoint in (src, dst):
            if endpoint not in self._nodes:
                raise KeyError(f"nó '{endpoint}' não existe — crie o nó antes da aresta")
        now = self._clock()
        key = (src, kind.value, dst)
        existing = self._edges.get(key)
        if existing is None:
            edge = Edge(
                src=src,
                dst=dst,
                kind=kind,
                attributes=dict(attributes),
                evidence=sorted(set(evidence or [])),
                first_seen=now,
                last_seen=now,
            )
            self._edges[key] = edge
            return edge
        existing.attributes.update(attributes)
        if evidence:
            existing.evidence = sorted(set(existing.evidence) | set(evidence))
        existing.last_seen = now
        return existing

    # ── consulta ────────────────────────────────────────────────────────────
    def node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def has_edge(self, src: str, kind: EdgeKind, dst: str) -> bool:
        return (src, kind.value, dst) in self._edges

    def nodes_by_kind(self, kind: NodeKind) -> list[Node]:
        return sorted((n for n in self._nodes.values() if n.kind == kind), key=lambda n: n.node_id)

    def find(self, *, kind: NodeKind | None = None, **attributes: str) -> list[Node]:
        """Nós que casam o tipo (se dado) e todos os atributos exatos informados."""
        out = []
        for node in self._nodes.values():
            if kind is not None and node.kind != kind:
                continue
            if all(node.attributes.get(k) == v for k, v in attributes.items()):
                out.append(node)
        return sorted(out, key=lambda n: n.node_id)

    def neighbors(
        self,
        node_id: str,
        *,
        kind: EdgeKind | None = None,
        direction: str = "out",
    ) -> list[Node]:
        """Nós vizinhos por direção (``out``/``in``/``both``) e tipo de aresta opcional."""
        ids: set[str] = set()
        for edge in self._edges.values():
            if kind is not None and edge.kind != kind:
                continue
            if direction in ("out", "both") and edge.src == node_id:
                ids.add(edge.dst)
            if direction in ("in", "both") and edge.dst == node_id:
                ids.add(edge.src)
        return sorted((self._nodes[i] for i in ids if i in self._nodes), key=lambda n: n.node_id)

    def edges(self) -> list[Edge]:
        return [self._edges[k] for k in sorted(self._edges)]

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ── histórico (diff) ────────────────────────────────────────────────────
    def diff(self, previous: KnowledgeGraph) -> GraphDiff:
        """Diferença deste grafo em relação a um anterior (o que mudou desde o último scan)."""
        cur_nodes, prev_nodes = set(self._nodes), set(previous._nodes)
        cur_edges, prev_edges = set(self._edges), set(previous._edges)
        return GraphDiff(
            added_nodes=sorted(cur_nodes - prev_nodes),
            removed_nodes=sorted(prev_nodes - cur_nodes),
            added_edges=sorted(cur_edges - prev_edges),
            removed_edges=sorted(prev_edges - cur_edges),
        )

    # ── serialização (persistência) ─────────────────────────────────────────
    def to_dict(self) -> dict[str, object]:
        return {
            "nodes": [self._nodes[i].to_dict() for i in sorted(self._nodes)],
            "edges": [e.to_dict() for e in self.edges()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KnowledgeGraph:
        graph = cls()
        for nd in data.get("nodes") or []:
            node = Node.from_dict(nd)
            graph._nodes[node.node_id] = node
        for ed in data.get("edges") or []:
            edge = Edge.from_dict(ed)
            graph._edges[edge.key] = edge
        return graph
