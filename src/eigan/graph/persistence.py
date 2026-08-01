"""Persistência do Knowledge Graph (Parte 2 — "o grafo deve ser permanente").

O grafo é um modelo vivo: cada execução **atualiza** o conhecimento existente, nunca
recomeça do zero. Este módulo grava/lê o grafo como JSON determinístico. A gravação é
**atômica** (arquivo temporário + `replace`) para nunca deixar um grafo meio-escrito em
disco. Ler um caminho inexistente devolve um grafo vazio (primeira execução).

Fluxo de acúmulo: ``g = load_graph(path); build_graph(findings, graph=g); save_graph(g,
path)`` — o conhecimento evolui entre scans (histórico via ``KnowledgeGraph.diff``).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from .graph import KnowledgeGraph


def save_graph(graph: KnowledgeGraph, path: str | Path) -> Path:
    """Grava o grafo em ``path`` como JSON determinístico, de forma atômica."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(graph.to_dict(), ensure_ascii=False, sort_keys=True, indent=2)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(p)  # troca atômica — nunca deixa arquivo meio-escrito
    return p


def load_graph(path: str | Path, *, clock: Callable[[], datetime] | None = None) -> KnowledgeGraph:
    """Lê o grafo de ``path``; caminho inexistente ⇒ grafo vazio (1ª execução)."""
    p = Path(path)
    if not p.exists():
        return KnowledgeGraph(clock=clock)
    data = json.loads(p.read_text(encoding="utf-8"))
    graph = KnowledgeGraph.from_dict(data)
    if clock is not None:
        graph._clock = clock  # novas inserções após a carga usam o relógio informado
    return graph
