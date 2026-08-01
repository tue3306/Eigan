"""Knowledge Graph do EIGAN — modelo vivo da superfície de ataque (Parte 2 do roadmap).

Nós e relacionamentos tipados, inserção idempotente, consulta, diff histórico e
serialização. O Correlation Engine e a IA consultam o grafo em vez de olhar findings
isolados.
"""

from .builder import build_graph
from .graph import GraphConflict, GraphDiff, KnowledgeGraph
from .model import Edge, EdgeKind, Node, NodeKind

__all__ = [
    "Edge",
    "EdgeKind",
    "GraphConflict",
    "GraphDiff",
    "KnowledgeGraph",
    "Node",
    "NodeKind",
    "build_graph",
]
