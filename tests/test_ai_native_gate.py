"""Gate AI-native (§0.4 / ADR-0012): nenhum caminho de **produto** produz scan sem provedor.

Prova por teste o invariante central da reconciliação IA-opcional × IA-obrigatória: os
pontos de entrada de **execução** de scan recusam com erro acionável quando não há
provedor de IA — **antes** de tocar rede, termo de uso ou consent gate. A API já cobre o
seu caminho (`POST /scans` → HTTP 428, ver ``test_api_scan``); aqui travamos o caminho da
**CLI** (``execute_scan`` e ``plan_scan`` em modo execução).

O substrato determinístico (``DeterministicPlanner``, quando o ``CognitiveEngine`` é
construído sem ``CompletionPort``) continua testável isolado — é o **piso de segurança**,
não um "modo sem IA" de produto (ver ``test_cognitive``). O gate de produto vive aqui, nos
entry points; o *dry-run* (preview que nada executa) é a única exceção legítima.
"""

from __future__ import annotations

import pytest

from eigan.ai.provider import AIProviderRequired
from eigan.cli.session import execute_scan, plan_scan
from eigan.engine.cognitive.goal import GoalKind
from eigan.perspective import Perspective


@pytest.fixture
def no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simula ausência de provedor de IA de forma robusta (independe de env/config)."""
    monkeypatch.setattr("eigan.ai.provider.default_provider", lambda *a, **k: None)


def test_cli_execute_scan_refuses_without_provider(no_provider, tmp_path) -> None:
    """``eigan scan`` (execute_scan) recusa antes de termo/consent/rede."""
    with pytest.raises(AIProviderRequired):
        execute_scan(
            targets=["example.com"],
            perspective=Perspective.EXTERNAL,
            profile="quick",
            scope_path=None,
            db=str(tmp_path / "e.db"),
            assume_yes=True,
            override_perspective=False,
            online_enrich=False,
        )


def test_cli_plan_execute_refuses_without_provider(no_provider, tmp_path) -> None:
    """``eigan plan --execute`` (plan_scan sem dry_run) exige provedor."""
    with pytest.raises(AIProviderRequired):
        plan_scan(
            goal_kind=GoalKind.ATTACK_SURFACE,
            targets=["example.com"],
            perspective=Perspective.EXTERNAL,
            profile="quick",
            scope_path=None,
            db=str(tmp_path / "e.db"),
            assume_yes=True,
            override_perspective=False,
            online_enrich=False,
            dry_run=False,
            use_ai=True,
        )


def test_cli_plan_dry_run_allowed_without_provider(no_provider, tmp_path) -> None:
    """Preview seguro (dry-run) **não** exige provedor — nada executa nem toca a rede."""
    outcome = plan_scan(
        goal_kind=GoalKind.ATTACK_SURFACE,
        targets=["example.com"],
        perspective=Perspective.EXTERNAL,
        profile="quick",
        scope_path=None,
        db=str(tmp_path / "e.db"),
        assume_yes=True,
        override_perspective=False,
        online_enrich=False,
        dry_run=True,
        use_ai=False,
    )
    assert outcome.report is None  # dry-run: nada executado
    assert outcome.ai_used is False
