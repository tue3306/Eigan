"""Integração AD: analisadores → sinais → cenários (TIER X.10/X.11).

Falha antes / passa depois: as saídas reais dos analisadores viram sinais corretos e
correlacionam em cenários; mapeamento honesto (kerberoasting crítico ⇒ conta
privilegiada; ESC1 ⇒ template vulnerável; shadow gravável ⇒ shadow+acl); sinal sem
evidência (coerção) não é fabricado.
"""

from __future__ import annotations

from eigan.analysis.ad import (
    AdAccount,
    AdObjectKeyCred,
    CertificateTemplate,
    NtlmHostConfig,
    PasswordPolicy,
    PwAccount,
    assess_kerberos,
    assess_ntlm,
    assess_passwords,
    assess_shadow_credentials,
    classify_adcs,
)
from eigan.analysis.ad.pipeline import analyze_ad_scenarios, to_ad_signals


def test_end_to_end_domain_compromise_scenario() -> None:
    kerb = assess_kerberos([AdAccount(sam="svc_sql", spns=["MSSQL/db"], privileged=True)])
    pw = assess_passwords(PasswordPolicy(min_length=6, lockout_threshold=0))
    scenarios = analyze_ad_scenarios(kerberos=kerb, password=pw)
    names = {sc.name for sc in scenarios}
    assert "Comprometimento de domínio via Kerberoasting" in names


def test_kerberoasting_signals_privileged_only_when_critical() -> None:
    # kerberoasting não-privilegiado (HIGH) NÃO emite privileged_account
    high = assess_kerberos([AdAccount(sam="svc", spns=["x/y"])])
    kinds = {s.kind for s in to_ad_signals(kerberos=high)}
    assert kinds == {"kerberoasting"}
    # privilegiado (CRITICAL) emite os dois
    crit = assess_kerberos([AdAccount(sam="svc", spns=["x/y"], privileged=True)])
    kinds = {s.kind for s in to_ad_signals(kerberos=crit)}
    assert kinds == {"kerberoasting", "privileged_account"}


def test_shadow_writable_produces_scenario_same_target() -> None:
    shadow = assess_shadow_credentials(
        [AdObjectKeyCred(name="user:bob", writable_by_low_priv=True)]
    )
    scenarios = analyze_ad_scenarios(shadow=shadow)
    assert [sc.name for sc in scenarios] == ["Persistência via Shadow Credentials"]


def test_esc1_and_esc4_yield_adcs_scenario() -> None:
    templates = [
        CertificateTemplate(
            name="UserAuth",
            client_authentication=True,
            enrollee_supplies_subject=True,
            low_privileged_enrollment=True,
        ),  # ESC1
        CertificateTemplate(name="UserAuth", vulnerable_acl=True),  # ESC4 → excessive_permissions
    ]
    escs = classify_adcs(templates)
    scenarios = analyze_ad_scenarios(adcs=escs)
    assert any(sc.name == "Escalada via AD CS (ESC1)" for sc in scenarios)


def test_ntlm_relay_not_fabricated_without_coercion() -> None:
    # NTLM sozinho emite smb_signing_disabled, mas NÃO ntlm_relay (sem detector de coerção)
    ntlm = assess_ntlm([NtlmHostConfig(host="fs01")])
    kinds = {s.kind for s in to_ad_signals(ntlm=ntlm)}
    assert "smb_signing_disabled" in kinds
    assert "ntlm_relay" not in kinds
    # portanto o cenário NTLM Relay não dispara (honesto)
    assert analyze_ad_scenarios(ntlm=ntlm) == []


def test_signals_are_deduplicated() -> None:
    pw = assess_passwords(
        PasswordPolicy(
            min_length=6, lockout_threshold=0
        ),  # 2 kinds → weak_password_policy (domain)
        accounts=[PwAccount(sam="admin", is_privileged=True, has_mfa=False)],
    )
    signals = to_ad_signals(password=pw)
    keys = [(s.kind, s.target) for s in signals]
    assert len(keys) == len(set(keys))  # sem duplicatas
    assert ("weak_password_policy", "domain") in keys
    assert ("mfa_absent", "admin") in keys
