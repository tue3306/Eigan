"""NTLM Security Assessment (TIER X.7).

Falha antes / passa depois: SMB/LDAP signing não exigido, LDAP sem channel binding e
NTLMv1 são sinalizados; em DC o LDAP vira crítico; host endurecido não gera nada;
ordenação por severidade.
"""

from __future__ import annotations

from eigan.analysis.ad.ntlm import NtlmHostConfig, assess_ntlm
from eigan.findings.schema import Severity


def test_flags_all_weaknesses() -> None:
    host = NtlmHostConfig(host="fs01")  # tudo desabilitado por padrão, exceto ntlmv1
    kinds = {f.kind for f in assess_ntlm([host])}
    assert kinds == {
        "smb_signing_not_required",
        "ldap_signing_not_required",
        "ldap_no_channel_binding",
    }


def test_ldap_on_dc_is_critical() -> None:
    dc = NtlmHostConfig(host="DC01", smb_signing_required=True, is_domain_controller=True)
    findings = assess_ntlm([dc])
    ldap = [f for f in findings if f.kind.startswith("ldap")]
    assert all(f.severity is Severity.CRITICAL for f in ldap)


def test_ntlmv1_is_critical() -> None:
    host = NtlmHostConfig(
        host="app",
        smb_signing_required=True,
        ldap_signing_required=True,
        ldap_channel_binding=True,
        ntlmv1_allowed=True,
    )
    findings = assess_ntlm([host])
    assert [f.kind for f in findings] == ["ntlmv1_allowed"]
    assert findings[0].severity is Severity.CRITICAL


def test_hardened_host_produces_nothing() -> None:
    host = NtlmHostConfig(
        host="secure",
        smb_signing_required=True,
        ldap_signing_required=True,
        ldap_channel_binding=True,
        ntlmv1_allowed=False,
    )
    assert assess_ntlm([host]) == []


def test_sorted_by_severity() -> None:
    dc = NtlmHostConfig(host="DC01", is_domain_controller=True)  # LDAP crítico + SMB alto
    findings = assess_ntlm([dc])
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].severity.rank >= findings[-1].severity.rank
