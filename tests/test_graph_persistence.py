"""Persistência do Knowledge Graph (Parte 2).

Falha antes / passa depois: save→load preserva o grafo (round-trip determinístico);
caminho inexistente devolve grafo vazio; a gravação é atômica; e o grafo acumula entre
cargas (memória viva).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from eigan.findings.schema import Finding, Severity
from eigan.graph import build_graph
from eigan.graph.model import NodeKind
from eigan.graph.persistence import load_graph, save_graph


class _Clock:
    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t += timedelta(seconds=1)
        return now


def _f(asset: str) -> Finding:
    return Finding(
        title="v", severity=Severity.HIGH, affected_asset=asset, source_tool="x", cwe="CWE-89"
    )


def test_save_load_round_trip(tmp_path) -> None:
    g = build_graph([_f("10.0.0.1")], clock=_Clock())
    path = tmp_path / "kg" / "graph.json"
    save_graph(g, path)
    assert path.exists()
    loaded = load_graph(path)
    assert loaded.to_dict() == g.to_dict()
    assert loaded.node("asset:10.0.0.1").kind is NodeKind.HOST


def test_missing_path_returns_empty_graph(tmp_path) -> None:
    g = load_graph(tmp_path / "inexistente.json")
    assert len(g) == 0


def test_save_is_atomic_no_tmp_left(tmp_path) -> None:
    g = build_graph([_f("10.0.0.1")], clock=_Clock())
    path = tmp_path / "graph.json"
    save_graph(g, path)
    # o arquivo temporário não fica para trás
    assert not (tmp_path / "graph.json.tmp").exists()


def test_graph_accumulates_across_loads(tmp_path) -> None:
    path = tmp_path / "graph.json"
    save_graph(build_graph([_f("10.0.0.1")], clock=_Clock()), path)
    # carrega, adiciona um ativo novo, salva de novo
    g = load_graph(path, clock=_Clock())
    build_graph([_f("10.0.0.2")], graph=g)
    save_graph(g, path)
    reloaded = load_graph(path)
    assert reloaded.node("asset:10.0.0.1") is not None
    assert reloaded.node("asset:10.0.0.2") is not None
