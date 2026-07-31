"""Estimativa de orçamento de IA no dry-run (§2.6): honesta, grounded, UNVERIFIED sem preço."""

from __future__ import annotations

from click.testing import CliRunner

from eigan.cli.main import cli
from eigan.observability.cost import CostModel, estimate_scan_budget


def test_estimate_tokens_and_unverified_without_price() -> None:
    est = estimate_scan_budget(
        capabilities=5, waves=3, model=None, cost_model=CostModel({}), max_output_tokens=4096
    )
    assert est.capabilities == 5
    assert est.planning_calls_min == 1
    assert est.planning_calls_max == 4  # 1 + 3 ondas
    assert est.total_output_tokens_max == 4 * 4096
    assert est.cost_max is None  # sem modelo/preço → UNVERIFIED (P1)


def test_estimate_cost_when_price_verified() -> None:
    cm = CostModel(
        {"m": {"verified": True, "input_per_1k": 1.0, "output_per_1k": 2.0, "currency": "USD"}}
    )
    est = estimate_scan_budget(
        capabilities=2, waves=1, model="m", cost_model=cm, max_output_tokens=1000
    )
    # planning_max=2 → total_out=2000 tokens de saída; 2000/1000 * 2.0 = 4.0 USD
    assert est.cost_max is not None
    assert est.cost_max.amount == 4.0 and est.cost_max.currency == "USD"


def test_estimate_unverified_when_model_has_no_price() -> None:
    est = estimate_scan_budget(
        capabilities=1, waves=0, model="sem-preco", cost_model=CostModel({}), max_output_tokens=100
    )
    assert est.planning_calls_max == 1  # só o plano inicial (0 ondas)
    assert est.cost_max is None  # nunca estima sem preço verificado (P1)


def test_plan_command_shows_budget_estimate(monkeypatch) -> None:
    # `eigan plan` (dry-run) apresenta a estimativa ANTES de qualquer execução.
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "EIGAN_AI_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    result = CliRunner().invoke(cli, ["plan", "example.com", "--goal", "attack-surface"])
    assert result.exit_code == 0
    assert "Estimativa de orçamento de IA" in result.output
    assert "UNVERIFIED" in result.output  # sem provedor/preço → honesto
