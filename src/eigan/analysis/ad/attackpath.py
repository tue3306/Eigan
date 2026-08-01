"""Attack Path Analysis de Active Directory (TIER X.2) — algoritmo próprio.

Dado o Knowledge Graph com objetos de AD e arestas de **escalonamento**
(`MEMBER_OF`, `HAS_CONTROL`, `ADMIN_TO`), encontra caminhos por onde um principal poderia
escalar privilégio até um alvo de alto valor (ex.: o grupo Domain Admins). É um problema
de alcançabilidade em grafo direcionado: a busca é própria (enumeração de caminhos
simples limitada em profundidade), determinística e baseada **apenas nas relações
coletadas** — nenhuma relação inventada (P1). Respeita o escopo/autorização como qualquer
análise (P3): opera sobre dados de um engajamento autorizado.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...graph.graph import KnowledgeGraph
from ...graph.model import Edge, EdgeKind

# Arestas que representam ganho de privilégio (um passo do caminho de ataque).
_ESCALATION: frozenset[EdgeKind] = frozenset(
    {EdgeKind.MEMBER_OF, EdgeKind.HAS_CONTROL, EdgeKind.ADMIN_TO}
)


@dataclass(frozen=True)
class PathStep:
    """Um passo do caminho: quem, por qual relação (e direito), alcança o quê."""

    src: str
    dst: str
    relation: str  # valor do EdgeKind (member_of / has_control / admin_to)
    right: str = ""  # para has_control: o direito de AD (GenericAll, WriteDacl, …)

    def describe(self) -> str:
        detail = f" ({self.right})" if self.right else ""
        return f"{self.src} --{self.relation}{detail}--> {self.dst}"


@dataclass(frozen=True)
class AttackPath:
    """Um caminho de escalonamento do principal inicial até o alvo."""

    steps: list[PathStep] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def start(self) -> str:
        return self.steps[0].src if self.steps else ""

    @property
    def target(self) -> str:
        return self.steps[-1].dst if self.steps else ""

    def describe(self) -> str:
        return " ⇒ ".join(step.describe() for step in self.steps)


def _step(edge: Edge) -> PathStep:
    return PathStep(
        src=edge.src,
        dst=edge.dst,
        relation=edge.kind.value,
        right=edge.attributes.get("right", ""),
    )


def _adjacency(graph: KnowledgeGraph) -> dict[str, list[Edge]]:
    """Adjacência determinística só com arestas de escalonamento."""
    adj: dict[str, list[Edge]] = {}
    for edge in graph.edges():
        if edge.kind in _ESCALATION:
            adj.setdefault(edge.src, []).append(edge)
    for src in adj:
        adj[src].sort(key=lambda e: (e.dst, e.kind.value, e.attributes.get("right", "")))
    return adj


def find_attack_paths(
    graph: KnowledgeGraph,
    *,
    start: str,
    target: str,
    max_depth: int = 8,
    limit: int = 100,
) -> list[AttackPath]:
    """Todos os caminhos simples de escalonamento de ``start`` a ``target``.

    Caminhos simples (sem repetir nó) até ``max_depth`` passos, ordenados do mais curto
    ao mais longo. ``limit`` limita a explosão combinatória — se atingido, a busca para
    (a poda é registrável pelo chamador). Determinístico."""
    adj = _adjacency(graph)
    results: list[AttackPath] = []

    def dfs(node: str, path: list[Edge], visited: frozenset[str]) -> None:
        if len(results) >= limit:
            return
        if node == target and path:
            results.append(AttackPath([_step(e) for e in path]))
            return
        if len(path) >= max_depth:
            return
        for edge in adj.get(node, []):
            if edge.dst in visited:
                continue  # caminho simples: não revisita nó (corta ciclos)
            dfs(edge.dst, [*path, edge], visited | {edge.dst})

    dfs(start, [], frozenset({start}))
    results.sort(key=lambda p: (p.length, tuple(s.dst for s in p.steps)))
    return results


def shortest_attack_path(
    graph: KnowledgeGraph, *, start: str, target: str, max_depth: int = 8
) -> AttackPath | None:
    """O caminho de escalonamento mais curto de ``start`` a ``target``, ou None."""
    paths = find_attack_paths(graph, start=start, target=target, max_depth=max_depth, limit=1_000)
    return paths[0] if paths else None
