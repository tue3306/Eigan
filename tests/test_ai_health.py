"""Monitoramento de degradação do componente agêntico (§19.3).

O report do scan carrega métricas de saúde da IA: chamadas de planejamento,
respostas inválidas (recurso ao substrato) e ids inventados descartados pelo
grounding. Alta taxa indica modelo trocado, prompt inchado ou provedor instável —
observável, não silencioso.
"""

from __future__ import annotations

from eigan.engine.cognitive import CognitiveEngine, Goal, GoalKind
from eigan.engine.registry import PluginRegistry
from eigan.perspective import Perspective
from eigan.security.onboarding import build_scope


class _BadJSON:
    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        return "isto nao e json valido"


class _Invented:
    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        return '{"plan": ["pwn", "port_discovery", "hack_all"], "next": [], "stop_when": "x"}'


class _Clean:
    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        return '{"plan": ["port_discovery", "web_probe"], "next": [], "stop_when": "x"}'


def _run(stub):
    engine = CognitiveEngine(PluginRegistry([]), completion=stub)  # registry vazio: determinístico
    scope = build_scope(None, ["example.com"], Perspective.EXTERNAL)
    return engine.run(Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"]), scope=scope)


def test_parse_failures_tracked_on_invalid_json() -> None:
    r = _run(_BadJSON())
    assert r.ai_parse_failures >= 1  # JSON inválido → recurso ao substrato, contabilizado
    assert r.ai_used is False  # caiu no determinístico (não é "modo sem IA")


def test_grounding_discards_tracked_on_invented_ids() -> None:
    r = _run(_Invented())
    assert r.ai_grounding_discards >= 2  # 'pwn' e 'hack_all' descartados pelo grounding
    assert r.ai_planner_calls >= 1
    assert r.ai_parse_failures == 0  # o JSON era válido; só os ids eram inventados


def test_healthy_run_has_no_degradation() -> None:
    r = _run(_Clean())
    assert r.ai_parse_failures == 0 and r.ai_grounding_discards == 0
    assert r.ai_planner_calls >= 1
