"""Popula o Knowledge Graph a partir dos findings coletados (Parte 2 do roadmap).

Transforma a lista plana de findings num grafo tipado: cada ativo vira um nó, cada
finding vira um nó, e as relações (ativo **afetado por** finding; finding **referencia**
CWE/OWASP/MITRE) viram arestas com evidência (a ferramenta de origem). Só cria o que a
evidência sustenta — nenhuma relação inventada (P1). A construção é idempotente e
acumulativa: reexecutar sobre um grafo existente atualiza o conhecimento (memória viva),
sem apagar nada.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from ..findings.schema import Finding
from ..perspective import extract_host
from .graph import KnowledgeGraph
from .model import EdgeKind, NodeKind


def build_graph(
    findings: list[Finding],
    *,
    graph: KnowledgeGraph | None = None,
    clock: Callable[[], datetime] | None = None,
) -> KnowledgeGraph:
    """Constrói (ou atualiza) o grafo a partir dos findings. Devolve o grafo."""
    g = graph if graph is not None else KnowledgeGraph(clock=clock)

    for finding in findings:
        host = extract_host(finding.affected_asset)
        asset_id = f"asset:{host}"
        g.add_node(asset_id, NodeKind.HOST, label=host, perspective=finding.perspective.value)

        finding_id = f"finding:{finding.fingerprint}"
        g.add_node(
            finding_id,
            NodeKind.FINDING,
            label=finding.title,
            severity=finding.severity.value,
            status=finding.status.value,
            source_tool=finding.source_tool,
        )
        g.add_edge(asset_id, finding_id, EdgeKind.AFFECTED_BY, evidence=[finding.source_tool])

        if finding.cwe:
            cwe_id = f"cwe:{finding.cwe.upper()}"
            g.add_node(cwe_id, NodeKind.CWE, label=finding.cwe.upper())
            g.add_edge(finding_id, cwe_id, EdgeKind.REFERENCES, evidence=[finding.source_tool])

        if finding.owasp:
            owasp_id = f"owasp:{finding.owasp}"
            g.add_node(owasp_id, NodeKind.OWASP, label=finding.owasp)
            g.add_edge(finding_id, owasp_id, EdgeKind.REFERENCES, evidence=[finding.source_tool])

        if finding.attack_technique:
            mitre_id = f"mitre:{finding.attack_technique}"
            g.add_node(mitre_id, NodeKind.MITRE_TECHNIQUE, label=finding.attack_technique)
            g.add_edge(finding_id, mitre_id, EdgeKind.REFERENCES, evidence=[finding.source_tool])

    return g
