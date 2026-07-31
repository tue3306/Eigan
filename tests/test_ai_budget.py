"""Teto de token/custo de IA que interrompe o scan (§2.1).

Garante que é impossível um scan exceder o orçamento de IA declarado: o loop
cognitivo encerra graciosamente ao atingir o teto de tokens (sempre confiável,
medido do provedor) ou de custo (só quando o preço é verificado — senão o token
governa, P1). A IA é obrigatória (ADR-0012): há sempre o plano inicial; o teto
interrompe as chamadas seguintes.
"""

from __future__ import annotations

import pytest

from eigan.engine.cognitive import Budget, CognitiveEngine, Goal, GoalKind, StopReason
from eigan.engine.registry import PluginRegistry
from eigan.observability.cost import CostModel
from eigan.observability.usage import TokenUsage, UsageEvent, record_completion
from eigan.perspective import Perspective
from eigan.security.onboarding import build_scope


def _record(engine: CognitiveEngine, prompt: int, completion: int) -> None:
    engine._scan_meter.record(UsageEvent("fake", "m", TokenUsage(prompt, completion)))


def test_budget_validates_ai_limits() -> None:
    with pytest.raises(ValueError):
        Budget(max_ai_tokens=0)
    with pytest.raises(ValueError):
        Budget(max_ai_cost_usd=0)
    Budget(max_ai_tokens=1, max_ai_cost_usd=0.01)  # válidos


def test_ai_budget_stop_on_tokens() -> None:
    engine = CognitiveEngine(PluginRegistry.discover())
    _record(engine, 30, 12)  # 42 tokens acumulados
    assert engine._ai_budget_stop(Budget(max_ai_tokens=100)) is None  # 42 < 100
    assert engine._ai_budget_stop(Budget()) is None  # sem teto → nunca para
    _record(engine, 40, 20)  # +60 = 102
    assert engine._ai_budget_stop(Budget(max_ai_tokens=100)) is StopReason.BUDGET_TOKENS


def test_ai_cost_ceiling_only_fires_when_price_verified() -> None:
    engine = CognitiveEngine(PluginRegistry.discover())
    engine._scan_meter.record(UsageEvent("fake", "priced", TokenUsage(1000, 1000)))
    # Sem preço verificado → custo UNVERIFIED → o teto de custo NÃO dispara (P1).
    engine._cost_model = CostModel({})
    assert engine._ai_budget_stop(Budget(max_ai_cost_usd=0.01)) is None
    # Com preço verificado → custo = (1+1) = 2.0 USD ≥ 0.01 → dispara.
    engine._cost_model = CostModel(
        {"priced": {"verified": True, "input_per_1k": 1.0, "output_per_1k": 1.0, "currency": "USD"}}
    )
    assert engine._ai_budget_stop(Budget(max_ai_cost_usd=0.01)) is StopReason.BUDGET_COST
    assert engine._ai_budget_stop(Budget(max_ai_cost_usd=10.0)) is None  # 2.0 < 10


class _MeteredFake:
    """Provedor de IA fake que mede 42 tokens por chamada (como o provedor HTTP real)."""

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        record_completion("fake", "m", {"usage": {"prompt_tokens": 30, "completion_tokens": 12}})
        return '{"plan": ["port_discovery"], "stop_when": "sem evidência"}'


def test_scan_stops_gracefully_when_token_ceiling_reached() -> None:
    # Teto (10) abaixo do plano inicial (42 tokens): o scan encerra na primeira
    # checagem do loop, SEM chamadas extras, e o report registra o encerramento.
    engine = CognitiveEngine(PluginRegistry.discover(), completion=_MeteredFake())
    scope = build_scope(None, ["example.com"], Perspective.EXTERNAL)
    goal = Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"], budget=Budget(max_ai_tokens=10))
    report = engine.run(goal, scope=scope)
    assert report.stop_reason is StopReason.BUDGET_TOKENS
    # nenhuma chamada além do plano inicial que estourou o teto minúsculo.
    assert report.token_usage.total_tokens == 42


def test_session_budget_helper() -> None:
    """A CLI/wizard traduz --max-tokens/--max-cost em Budget (§2.1)."""
    from eigan.cli.session import _budget

    assert _budget(None, None) is None  # sem teto → default do Goal
    b = _budget(500, None)
    assert b is not None and b.max_ai_tokens == 500 and b.max_ai_cost_usd is None
    b2 = _budget(None, 1.5)
    assert b2 is not None and b2.max_ai_cost_usd == 1.5
