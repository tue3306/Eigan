"""Knowledge Graph do EIGAN — modelo vivo da superfície de ataque (Parte 2 do roadmap).

Nós e relacionamentos tipados, inserção idempotente, consulta, diff histórico e
serialização. O Correlation Engine e a IA consultam o grafo em vez de olhar findings
isolados.
"""

from .builder import build_graph
from .correlation import AttackChain, AttackStep, correlate_attack_chains
from .graph import GraphConflict, GraphDiff, KnowledgeGraph
from .model import Edge, EdgeKind, Node, NodeKind
from .persistence import load_graph, save_graph
from .query import (
    assets_added_since,
    assets_affected_by,
    reference_prevalence,
    riskiest_assets,
)

__all__ = [
    "AttackChain",
    "AttackStep",
    "Edge",
    "EdgeKind",
    "GraphConflict",
    "GraphDiff",
    "KnowledgeGraph",
    "Node",
    "NodeKind",
    "assets_added_since",
    "assets_affected_by",
    "build_graph",
    "correlate_attack_chains",
    "load_graph",
    "reference_prevalence",
    "riskiest_assets",
    "save_graph",
]
