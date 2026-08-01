"""Regras de Engajamento como artefato de 1ª classe (§18.1).

Falha antes / passa depois: o RoE bloqueia ação fora da janela, contra host/porta/path
excluído e acima da classe de teste autorizada; o digest é determinístico; carrega de
YAML; e a violação é capturável como violação de escopo (P3).
"""

from __future__ import annotations

from datetime import datetime, time

import pytest

from eigan.policy.impact import ImpactClass
from eigan.policy.roe import (
    Action,
    RateLimit,
    RoEViolation,
    RulesOfEngagement,
    TimeWindow,
)
from eigan.security.scope import ScopeViolation

# 2026-08-03 é uma segunda-feira; 2026-08-08 é um sábado.
_MON_10H = datetime(2026, 8, 3, 10, 0)
_MON_22H = datetime(2026, 8, 3, 22, 0)
_SAT_10H = datetime(2026, 8, 8, 10, 0)


def _recon(target: str = "10.0.0.1", **kw) -> Action:
    return Action(target=target, impact=ImpactClass.ACTIVE_SAFE, at=_MON_10H, **kw)


def test_empty_roe_allows_everything_in_scope() -> None:
    roe = RulesOfEngagement(max_impact=ImpactClass.STATE_CHANGING)
    assert roe.evaluate(_recon()).allowed is True


def test_blocks_outside_time_window() -> None:
    business = TimeWindow(weekdays=frozenset(range(5)), start=time(9, 0), end=time(18, 0))
    roe = RulesOfEngagement(windows=[business])
    assert roe.evaluate(_recon()).allowed is True  # segunda 10h — dentro
    blocked = roe.evaluate(Action("10.0.0.1", ImpactClass.ACTIVE_SAFE, _MON_22H))
    assert blocked.allowed is False and "blackout" in blocked.reason
    weekend = roe.evaluate(Action("10.0.0.1", ImpactClass.ACTIVE_SAFE, _SAT_10H))
    assert weekend.allowed is False  # sábado fora dos dias úteis


def test_overnight_window_crosses_midnight() -> None:
    night = TimeWindow(start=time(22, 0), end=time(6, 0))
    roe = RulesOfEngagement(windows=[night])
    assert roe.evaluate(Action("10.0.0.1", ImpactClass.ACTIVE_SAFE, _MON_22H)).allowed is True
    assert roe.evaluate(_recon()).allowed is False  # 10h fora da janela noturna


def test_blocks_excluded_host_and_cidr() -> None:
    roe = RulesOfEngagement(exclude_hosts=["10.0.0.5", "192.168.1.0/24"])
    assert roe.evaluate(_recon("10.0.0.5")).allowed is False
    assert roe.evaluate(_recon("192.168.1.42")).allowed is False  # dentro do CIDR excluído
    assert roe.evaluate(_recon("10.0.0.1")).allowed is True


def test_blocks_excluded_port_and_path() -> None:
    roe = RulesOfEngagement(exclude_ports=frozenset({3389, 5432}), exclude_paths=["/admin"])
    assert roe.evaluate(_recon(port=3389)).allowed is False
    assert roe.evaluate(_recon(port=80)).allowed is True
    assert roe.evaluate(_recon(path="/admin/login")).allowed is False


def test_blocks_impact_above_authorized() -> None:
    roe = RulesOfEngagement(max_impact=ImpactClass.ACTIVE_SAFE)
    exploit = Action("10.0.0.1", ImpactClass.EXPLOIT_VALIDATION, _MON_10H)
    decision = roe.evaluate(exploit)
    assert decision.allowed is False and "acima do autorizado" in decision.reason
    assert roe.evaluate(_recon()).allowed is True  # recon segue permitido


def test_check_raises_roe_violation_as_scope_violation() -> None:
    roe = RulesOfEngagement(max_impact=ImpactClass.PASSIVE)
    exploit = Action("10.0.0.1", ImpactClass.STATE_CHANGING, _MON_10H)
    with pytest.raises(RoEViolation):
        roe.check(exploit)
    # handler que barra escopo também barra RoE (defesa em profundidade)
    with pytest.raises(ScopeViolation):
        roe.check(exploit)


def test_rate_limit_min_interval() -> None:
    assert RateLimit(max_per_second=2).min_interval_seconds() == 0.5
    assert RateLimit(max_per_minute=60).min_interval_seconds() == 1.0
    # o mais restritivo vence: 5/s = 0.2s vs 60/min = 1.0s → 1.0s
    assert RateLimit(max_per_second=5, max_per_minute=60).min_interval_seconds() == 1.0
    assert RateLimit().min_interval_seconds() is None


def test_digest_is_deterministic_and_sensitive() -> None:
    a = RulesOfEngagement(engagement="e", exclude_hosts=["10.0.0.5"], exclude_ports=frozenset({22}))
    b = RulesOfEngagement(engagement="e", exclude_ports=frozenset({22}), exclude_hosts=["10.0.0.5"])
    assert a.digest() == b.digest()  # ordem de entrada não altera o digest
    c = RulesOfEngagement(engagement="e", exclude_hosts=["10.0.0.6"])
    assert a.digest() != c.digest()  # mudança de conteúdo muda o digest


def test_from_yaml_round_trip(tmp_path) -> None:
    path = tmp_path / "roe.yaml"
    path.write_text(
        "engagement: cliente-x\n"
        "windows:\n"
        "  - weekdays: [mon, tue, wed, thu, fri]\n"
        "    start: '09:00'\n"
        "    end: '18:00'\n"
        "exclude_hosts: ['prod.example.com']\n"
        "exclude_ports: [3389]\n"
        "max_impact: active_safe\n"
        "rate_limit: {max_per_second: 10}\n"
        "emergency_contacts: ['soc@example.com']\n",
        encoding="utf-8",
    )
    roe = RulesOfEngagement.from_yaml(path)
    assert roe.engagement == "cliente-x"
    assert roe.max_impact is ImpactClass.ACTIVE_SAFE
    assert roe.rate_limit.min_interval_seconds() == 0.1
    # exploração é bloqueada; recon em horário comercial passa
    assert (
        roe.evaluate(Action("app.example.com", ImpactClass.EXPLOIT_VALIDATION, _MON_10H)).allowed
        is False
    )
    assert (
        roe.evaluate(Action("app.example.com", ImpactClass.ACTIVE_SAFE, _MON_10H)).allowed is True
    )
