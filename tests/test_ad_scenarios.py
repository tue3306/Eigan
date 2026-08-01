"""Correlação inteligente de sinais de AD em cenários (TIER X.11).

Falha antes / passa depois: combinações conhecidas viram um cenário único priorizado;
falta um sinal ⇒ sem cenário; regras com same_target exigem alvo comum; ordenação por
severidade/confiança; nada disparado sem sinais.
"""

from __future__ import annotations

from eigan.analysis.ad.scenarios import AdSignal, correlate_scenarios
from eigan.findings.schema import Severity


def test_kerberoasting_domain_compromise_scenario() -> None:
    signals = [
        AdSignal("kerberoasting", "svc_sql", Severity.HIGH),
        AdSignal("privileged_account", "svc_sql", Severity.HIGH),
        AdSignal("weak_password_policy", "CORP", Severity.MEDIUM),
    ]
    scenarios = correlate_scenarios(signals)
    assert len(scenarios) == 1
    sc = scenarios[0]
    assert sc.name == "Comprometimento de domínio via Kerberoasting"
    assert sc.severity is Severity.CRITICAL
    assert len(sc.signals) == 3  # os três sinais viram UM cenário (sem duplicação)
    assert sc.confidence == 100


def test_missing_signal_yields_no_scenario() -> None:
    # sem a política de senha fraca, o cenário de comprometimento não dispara
    signals = [
        AdSignal("kerberoasting", "svc_sql"),
        AdSignal("privileged_account", "svc_sql"),
    ]
    assert correlate_scenarios(signals) == []


def test_same_target_rule_requires_shared_target() -> None:
    # shadow_credentials + acl_misconfig no MESMO objeto
    same = [
        AdSignal("shadow_credentials", "user:bob"),
        AdSignal("acl_misconfig", "user:bob"),
    ]
    assert len(correlate_scenarios(same)) == 1
    # alvos diferentes → não correlaciona
    different = [
        AdSignal("shadow_credentials", "user:bob"),
        AdSignal("acl_misconfig", "user:alice"),
    ]
    assert correlate_scenarios(different) == []


def test_ntlm_relay_and_spraying_scenarios() -> None:
    signals = [
        AdSignal("ntlm_relay", "fileserver"),
        AdSignal("smb_signing_disabled", "fileserver"),
        AdSignal("password_spraying", "CORP"),
        AdSignal("mfa_absent", "CORP"),
    ]
    names = {sc.name for sc in correlate_scenarios(signals)}
    assert names == {"NTLM Relay", "Password Spraying sem MFA"}


def test_scenarios_sorted_by_severity() -> None:
    signals = [
        AdSignal("ntlm_relay", "h"),
        AdSignal("smb_signing_disabled", "h"),
        AdSignal("esc1", "T"),
        AdSignal("vulnerable_template", "T"),
        AdSignal("excessive_permissions", "T"),
    ]
    scenarios = correlate_scenarios(signals)
    assert scenarios[0].severity is Severity.CRITICAL  # ESC1 (crítico) antes do NTLM (alto)
    assert scenarios[0].severity.rank >= scenarios[-1].severity.rank


def test_no_signals_no_scenarios() -> None:
    assert correlate_scenarios([]) == []
