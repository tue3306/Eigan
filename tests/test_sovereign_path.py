"""Caminho Ollama custo-zero de 1ª classe (§2.8), hermético via provedor local stub.

Prova que o pipeline (plan → scan → enrichment) roda **fim a fim** com um provedor
LOCAL, sem rede e sem custo de API. Precisão conceitual (P5): é o caminho **sem custo
de API**, NÃO "sem IA" — o stub local **é** um provedor; a IA continua comandando o
scan. Mantém o CI hermético (liga ao §0.4): nenhuma chave, nenhuma rede.
"""

from __future__ import annotations

from pathlib import Path

from eigan.ai.provider import Enricher, Explanation
from eigan.engine.cognitive import CognitiveEngine, Goal, GoalKind
from eigan.engine.registry import PluginRegistry
from eigan.findings.schema import Finding, Severity
from eigan.knowledge.loader import KnowledgeBase
from eigan.perspective import Perspective
from eigan.security.onboarding import build_scope

_KB = Path(__file__).resolve().parents[1] / "knowledge" / "skills"


class _LocalStub:
    """Provedor de IA LOCAL de teste (semântica Ollama: sem rede, sem custo)."""

    def __init__(self) -> None:
        self.explain_calls = 0

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        return '{"plan": ["port_discovery"], "next": [], "stop_when": "sem evidência"}'

    def explain(self, finding: Finding, context: str) -> Explanation:
        self.explain_calls += 1
        return Explanation(text="analise local", remediation="r", ai_generated=True)


def _f(sev: Severity, asset: str, cwe: str) -> Finding:
    return Finding(title="T", severity=sev, affected_asset=asset, source_tool="t", cwe=cwe)


def test_full_pipeline_runs_with_local_stub_provider() -> None:
    stub = _LocalStub()
    # plan + scan: a IA (provedor LOCAL) comanda o plano fim a fim.
    engine = CognitiveEngine(PluginRegistry.discover(), completion=stub)
    scope = build_scope(None, ["example.com"], Perspective.EXTERNAL)
    report = engine.run(Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"]), scope=scope)
    assert report.planner_name == "agentic"  # a IA local comandou (não é "modo sem IA")
    assert report.ai_used is True

    # enrichment (análise/narrativa) com o MESMO provedor local — pipeline completo.
    enr = Enricher(KnowledgeBase(_KB), provider=stub)
    exps = enr.explain_all([_f(Severity.HIGH, "a", "CWE-89")])
    assert exps[0].ai_generated is True  # analisado pela IA local
    assert stub.explain_calls >= 1


def test_local_provider_is_ai_not_deterministic_mode() -> None:
    # P5: com provedor local, o planner é o agêntico (IA), não o substrato — deixa
    # inequívoco que "custo zero" ≠ "sem IA".
    engine = CognitiveEngine(PluginRegistry.discover(), completion=_LocalStub())
    scope = build_scope(None, ["example.com"], Perspective.EXTERNAL)
    report = engine.run(Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"]), scope=scope)
    assert report.planner_name == "agentic" and report.ai_used is True
