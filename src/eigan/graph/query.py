"""Consultas inteligentes e Impact Analysis sobre o Knowledge Graph (Parte 2).

Responde perguntas navegando o grafo, em vez de varrer findings soltos:

- **Impact Analysis:** dada uma referência (CWE/OWASP/MITRE), quais ativos são afetados?
- **Histórico:** quais ativos surgiram desde um instante (novos na superfície)?
- **Prevalência:** quais referências (ex.: CWEs) são mais presentes?
- **Risco:** quais ativos representam maior risco? (via Correlation Engine, ADR-0041)

Tudo determinístico e baseado só no que o grafo contém — nenhuma relação inventada (P1).
As respostas são o insumo que a IA usa para responder em linguagem natural (modo online).
"""

from __future__ import annotations

from datetime import datetime

from .correlation import AttackChain, correlate_attack_chains
from .graph import KnowledgeGraph
from .model import EdgeKind, Node, NodeKind


def assets_affected_by(graph: KnowledgeGraph, reference_id: str) -> list[Node]:
    """Impact Analysis: ativos afetados por uma referência (ex.: ``cwe:CWE-89``).

    Navega: referência ← (REFERENCES) findings ← (AFFECTED_BY) ativos."""
    findings = graph.neighbors(reference_id, kind=EdgeKind.REFERENCES, direction="in")
    asset_ids: set[str] = set()
    for finding in findings:
        for asset in graph.neighbors(finding.node_id, kind=EdgeKind.AFFECTED_BY, direction="in"):
            if asset.kind is NodeKind.HOST:
                asset_ids.add(asset.node_id)
    node_list = (graph.node(i) for i in asset_ids)
    return sorted((n for n in node_list if n is not None), key=lambda n: n.node_id)


def assets_added_since(graph: KnowledgeGraph, when: datetime) -> list[Node]:
    """Histórico: ativos (HOST) cujo ``first_seen`` é >= ``when`` (novos na superfície)."""
    return sorted(
        (
            n
            for n in graph.nodes_by_kind(NodeKind.HOST)
            if n.first_seen is not None and n.first_seen >= when
        ),
        key=lambda n: n.node_id,
    )


def reference_prevalence(
    graph: KnowledgeGraph, *, kind: NodeKind = NodeKind.CWE
) -> list[tuple[str, int]]:
    """Prevalência: quantos findings referenciam cada nó do tipo dado, do maior ao menor.

    Ex.: quais CWEs (ou OWASP/MITRE) aparecem mais na superfície."""
    counts: list[tuple[str, int]] = []
    for ref in graph.nodes_by_kind(kind):
        referencing = graph.neighbors(ref.node_id, kind=EdgeKind.REFERENCES, direction="in")
        counts.append((ref.label, len(referencing)))
    counts.sort(key=lambda pair: (-pair[1], pair[0]))
    return counts


def riskiest_assets(graph: KnowledgeGraph, *, top: int | None = None) -> list[AttackChain]:
    """Ativos de maior risco, como cadeias priorizadas (Correlation Engine)."""
    chains = correlate_attack_chains(graph)
    return chains[:top] if top is not None else chains
