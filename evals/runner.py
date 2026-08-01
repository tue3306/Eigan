"""Runner do harness de avaliação (§3.1): carrega cenários e roda o Planner offline.

Determinístico e sem rede: o planner determinístico é o substrato; para avaliar o
AgenticPlanner sem chave, injeta-se um ``CompletionPort`` stub (ver ``test_evals``).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from eigan.engine.cascade import CascadeGraph
from eigan.engine.cognitive.feedback import ScanState
from eigan.engine.cognitive.goal import Goal, GoalKind
from eigan.engine.cognitive.planner import DeterministicPlanner, Planner
from eigan.engine.registry import PluginRegistry
from eigan.findings.schema import Finding, Severity
from eigan.perspective import Perspective

from .schema import FindingSpec, Scenario

_SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


def load_scenarios(directory: Path | None = None) -> list[Scenario]:
    directory = directory or _SCENARIO_DIR
    out: list[Scenario] = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out.append(Scenario.model_validate(data))
    return out


def build_finding(spec: FindingSpec) -> Finding:
    return Finding(
        title=spec.title,
        severity=Severity(spec.severity),
        affected_asset=spec.affected_asset,
        source_tool=spec.source_tool,
        cwe=spec.cwe,
    )


def deterministic_planner(registry: PluginRegistry) -> DeterministicPlanner:
    return DeterministicPlanner(registry, CascadeGraph.from_registry(registry))


def produced_capabilities(
    scenario: Scenario, *, registry: PluginRegistry, planner: Planner
) -> list[str]:
    """Capacidades produzidas para o cenário: plano inicial + replan pelas findings
    injetadas. Determinístico e offline."""
    goal = Goal.build(
        GoalKind.from_str(scenario.goal_kind),
        scenario.targets,
        perspective=Perspective(scenario.perspective) if scenario.perspective else None,
        profile=scenario.profile,
    )
    plan = planner.initial_plan(goal)
    if scenario.findings:
        state = ScanState()
        for spec in scenario.findings:
            finding = build_finding(spec)
            state.findings.append(finding)
            state.new_findings.append(finding)
        planner.replan(goal, state, plan)
    return [c.value for c in plan.capabilities()]
