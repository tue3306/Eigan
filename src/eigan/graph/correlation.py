"""Correlation Engine sobre o Knowledge Graph — cadeias de ataque e confiança (Parte 1).

Deixa de olhar cada finding isolado: a partir do grafo (ADR-0039/0040), correlaciona as
exposições de um ativo numa **cadeia de ataque possível**, com **confidence score**
(0-100) baseado em evidência e diversidade de ferramentas, **risco contextual** e uma
**narrativa determinística**. É complementar a `engine.correlation.correlate_assets`
(agrupamento por ativo) — aqui a fonte de verdade é o grafo e a saída é a cadeia
priorizada.

Honestidade (P1/P2): a cadeia é uma **heurística rotulada como tal** — nenhuma relação é
inventada, só se correlaciona o que o grafo (e portanto a evidência) contém. O
encadeamento cross-asset (via topologia CONNECTED_TO/COMMUNICATES_WITH) entra quando
houver essas arestas; hoje a cadeia é por ativo, honestamente.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..findings.schema import Severity
from .graph import KnowledgeGraph
from .model import EdgeKind, Node, NodeKind


@dataclass(frozen=True)
class AttackStep:
    """Um passo da cadeia: uma exposição do ativo, com referências e evidência."""

    node_id: str
    label: str
    severity: str
    references: list[str] = field(default_factory=list)  # rótulos CWE/OWASP/MITRE
    evidence: list[str] = field(default_factory=list)  # ferramentas de origem


@dataclass(frozen=True)
class AttackChain:
    """Cadeia de ataque possível sobre um ativo, com confiança e risco contextual."""

    asset: str
    steps: list[AttackStep]
    confidence: int  # 0-100
    risk_score: int  # 0-100
    narrative: str

    @property
    def is_chain(self) -> bool:
        """Há progressão real (≥2 exposições correlacionadas)?"""
        return len(self.steps) >= 2


def compute_confidence(distinct_tools: int, total_evidence: int) -> int:
    """Confiança 0-100, transparente e baseada em evidência (§Correlation Engine).

    Sobe com a **diversidade de ferramentas** (confirmação por fontes independentes) e
    com a **corroboração** extra. Fórmula explícita — nada oculto (P2)."""
    base = 25
    diversity = max(0, distinct_tools - 1) * 20
    corroboration = max(0, total_evidence - distinct_tools) * 5
    return max(0, min(100, base + diversity + corroboration))


def _risk_score(max_sev_rank: int, confidence: int, breadth: int) -> int:
    """Risco contextual 0-100: severidade máxima modulada pela confiança e pela largura
    (nº de exposições correlacionadas). Não é só CVSS — considera o contexto do ativo."""
    sev_component = max_sev_rank * 20 + 20  # info=20 … critical=100
    modulated = sev_component * (0.6 + 0.4 * confidence / 100)
    return max(0, min(100, round(modulated) + min(max(0, breadth - 1), 3) * 2))


def _severity_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return 0


def _references(graph: KnowledgeGraph, finding_id: str) -> list[str]:
    refs = graph.neighbors(finding_id, kind=EdgeKind.REFERENCES, direction="out")
    return sorted(n.label for n in refs)


def _narrative(asset: str, steps: list[AttackStep], confidence: int, risk: int) -> str:
    """Narrativa técnica determinística (a narrativa rica via IA é o modo online)."""
    if not steps:
        return ""
    exposicoes = "; ".join(f"{s.label} ({s.severity})" for s in steps)
    verbo = "encadeando" if len(steps) >= 2 else "explorando"
    return (
        f"No ativo {asset}, um atacante poderia correlacionar as exposições — {exposicoes} — "
        f"{verbo} da menor para a maior severidade até o impacto mais grave. "
        f"Cadeia heurística (confiança {confidence}%, risco {risk}/100), "
        f"baseada apenas nas evidências coletadas."
    )


def _affected_evidence(graph: KnowledgeGraph, asset_id: str) -> dict[str, list[str]]:
    """Evidência (ferramentas) de cada aresta ativo AFFECTED_BY finding."""
    out: dict[str, list[str]] = {}
    for edge in graph.edges():
        if edge.src == asset_id and edge.kind is EdgeKind.AFFECTED_BY:
            out[edge.dst] = list(edge.evidence)
    return out


def _chain_for_asset(graph: KnowledgeGraph, asset: Node) -> AttackChain | None:
    findings = graph.neighbors(asset.node_id, kind=EdgeKind.AFFECTED_BY, direction="out")
    findings = [f for f in findings if f.kind is NodeKind.FINDING]
    if not findings:
        return None
    evidence_by_finding = _affected_evidence(graph, asset.node_id)

    steps = [
        AttackStep(
            node_id=f.node_id,
            label=f.label,
            severity=f.attributes.get("severity", "info"),
            references=_references(graph, f.node_id),
            evidence=sorted(evidence_by_finding.get(f.node_id, [])),
        )
        for f in findings
    ]
    # ordena da menor para a maior severidade (leitura como escalada)
    steps.sort(key=lambda s: (_severity_rank(s.severity), s.label))

    all_tools = {t for s in steps for t in s.evidence}
    total_evidence = sum(len(s.evidence) for s in steps)
    confidence = compute_confidence(len(all_tools), total_evidence)
    max_sev = max(_severity_rank(s.severity) for s in steps)
    risk = _risk_score(max_sev, confidence, len(steps))
    return AttackChain(
        asset=asset.label or asset.node_id,
        steps=steps,
        confidence=confidence,
        risk_score=risk,
        narrative=_narrative(asset.label or asset.node_id, steps, confidence, risk),
    )


def correlate_attack_chains(graph: KnowledgeGraph) -> list[AttackChain]:
    """Correlaciona as exposições de cada ativo em cadeias, ordenadas por risco."""
    chains = [
        chain
        for asset in graph.nodes_by_kind(NodeKind.HOST)
        if (chain := _chain_for_asset(graph, asset)) is not None
    ]
    chains.sort(key=lambda c: (c.risk_score, c.confidence), reverse=True)
    return chains
