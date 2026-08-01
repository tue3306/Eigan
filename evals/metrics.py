"""Métricas de avaliação de decisão (§3.1): recall, precisão de exclusão, ordem.

São métricas de DECISÃO (o plano acertou as capacidades certas, na ordem certa),
complementares às de custo/latência (que reusam ``observability/``). Puras e
determinísticas — o mesmo plano produz sempre o mesmo veredito.
"""

from __future__ import annotations

from pydantic import BaseModel

from .schema import Expected


class ScenarioMetrics(BaseModel):
    name: str
    recall: float  # fração das capacidades exigidas que apareceram no plano
    include_hits: list[str]
    include_misses: list[str]
    exclude_violations: list[str]  # capacidades proibidas que apareceram
    ordering_ok: bool
    passed: bool


def _precedes(seq: list[str], a: str, b: str) -> bool:
    return a in seq and b in seq and seq.index(a) < seq.index(b)


def evaluate(name: str, produced: list[str], expected: Expected) -> ScenarioMetrics:
    hits = [c for c in expected.must_include if c in produced]
    misses = [c for c in expected.must_include if c not in produced]
    recall = len(hits) / len(expected.must_include) if expected.must_include else 1.0
    exclude_violations = [c for c in expected.must_exclude if c in produced]
    ordering_ok = all(_precedes(produced, a, b) for a, b in expected.must_precede)
    passed = not misses and not exclude_violations and ordering_ok
    return ScenarioMetrics(
        name=name,
        recall=recall,
        include_hits=hits,
        include_misses=misses,
        exclude_violations=exclude_violations,
        ordering_ok=ordering_ok,
        passed=passed,
    )
