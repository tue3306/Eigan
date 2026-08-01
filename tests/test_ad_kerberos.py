"""Kerberos Security Assessment (TIER X.3).

Falha antes / passa depois: kerberoasting só para conta de usuário habilitada com SPN
(crítica se privilegiada); AS-REP para sem-preauth; unconstrained só fora de DC; CD e
RBCD sinalizados; conta desabilitada não gera nada; ordenação por severidade.
"""

from __future__ import annotations

from eigan.analysis.ad.kerberos import AdAccount, assess_kerberos
from eigan.findings.schema import Severity


def test_kerberoasting_user_with_spn() -> None:
    acc = AdAccount(sam="svc_sql", spns=["MSSQL/db01"])
    findings = assess_kerberos([acc])
    assert [f.kind for f in findings] == ["kerberoasting"]
    assert findings[0].severity is Severity.HIGH


def test_kerberoasting_privileged_is_critical() -> None:
    acc = AdAccount(sam="svc_admin", spns=["HTTP/app"], privileged=True)
    assert assess_kerberos([acc])[0].severity is Severity.CRITICAL


def test_computer_account_with_spn_is_not_kerberoasting() -> None:
    # computadores têm SPN por natureza — não é kerberoasting
    acc = AdAccount(sam="DC01$", is_user=False, spns=["HOST/dc01"])
    assert [f.kind for f in assess_kerberos([acc])] == []


def test_asrep_roasting() -> None:
    acc = AdAccount(sam="alice", dont_require_preauth=True)
    assert [f.kind for f in assess_kerberos([acc])] == ["asrep_roasting"]


def test_unconstrained_delegation_only_off_dc() -> None:
    off_dc = AdAccount(sam="app01$", is_user=False, unconstrained_delegation=True)
    assert [f.kind for f in assess_kerberos([off_dc])] == ["unconstrained_delegation"]
    # num DC, delegação irrestrita é legítima → não sinaliza
    dc = AdAccount(
        sam="DC01$", is_user=False, unconstrained_delegation=True, is_domain_controller=True
    )
    assert assess_kerberos([dc]) == []


def test_constrained_and_rbcd() -> None:
    cd = AdAccount(sam="web01$", is_user=False, constrained_delegation_targets=["CIFS/fs01"])
    rbcd = AdAccount(sam="app02$", is_user=False, rbcd_configured=True)
    kinds = {f.kind for f in assess_kerberos([cd, rbcd])}
    assert kinds == {"constrained_delegation", "rbcd"}


def test_disabled_account_produces_nothing() -> None:
    acc = AdAccount(sam="old_svc", enabled=False, spns=["HTTP/x"], dont_require_preauth=True)
    assert assess_kerberos([acc]) == []


def test_sorted_by_severity() -> None:
    accounts = [
        AdAccount(sam="a", dont_require_preauth=True),  # HIGH
        AdAccount(sam="b", spns=["x/y"], privileged=True),  # CRITICAL
    ]
    findings = assess_kerberos(accounts)
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].severity.rank >= findings[-1].severity.rank
