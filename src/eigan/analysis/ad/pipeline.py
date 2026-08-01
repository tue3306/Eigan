"""Integração dos analisadores de AD → sinais → cenários (TIER X.10/X.11).

Cola as saídas dos analisadores (Kerberos, AD CS/ESC, senha, NTLM, Shadow Credentials)
num vocabulário comum de :class:`AdSignal` e as correlaciona em cenários priorizados
(`correlate_scenarios`). O mapeamento é **honesto** (P1): um sinal só é emitido quando o
finding realmente o implica (ex.: só kerberoasting **crítico** implica conta
privilegiada; só ESC1 implica template vulnerável). Sinais que dependem de detecção ainda
inexistente (ex.: coerção `ntlm_relay`) **não** são fabricados — o cenário correspondente
simplesmente não dispara até haver evidência.
"""

from __future__ import annotations

from ...findings.schema import Severity
from .adcs import EscFinding
from .kerberos import KerberosFinding
from .ntlm import NtlmFinding
from .password import PasswordFinding
from .scenarios import AdSignal, AttackScenario, correlate_scenarios
from .shadowcreds import ShadowCredFinding

_WEAK_POLICY_KINDS = {"no_account_lockout", "weak_min_length", "no_complexity"}


def to_ad_signals(
    *,
    kerberos: list[KerberosFinding] | None = None,
    adcs: list[EscFinding] | None = None,
    password: list[PasswordFinding] | None = None,
    ntlm: list[NtlmFinding] | None = None,
    shadow: list[ShadowCredFinding] | None = None,
) -> list[AdSignal]:
    """Converte as saídas dos analisadores num conjunto deduplicado de sinais."""
    signals: list[AdSignal] = []

    for kf in kerberos or []:
        if kf.kind == "kerberoasting":
            signals.append(AdSignal("kerberoasting", kf.account, kf.severity))
            if kf.severity is Severity.CRITICAL:  # kerberoasting crítico = conta privilegiada
                signals.append(AdSignal("privileged_account", kf.account, kf.severity))

    for pf in password or []:
        if pf.kind in _WEAK_POLICY_KINDS:
            signals.append(AdSignal("weak_password_policy", pf.target, pf.severity))
        elif pf.kind == "privileged_without_mfa":
            signals.append(AdSignal("mfa_absent", pf.target, pf.severity))
            signals.append(AdSignal("privileged_account", pf.target, pf.severity))

    for ef in adcs or []:
        if ef.esc == "ESC1":
            signals.append(AdSignal("esc1", ef.target, ef.severity))
            signals.append(AdSignal("vulnerable_template", ef.target, ef.severity))
        elif ef.esc == "ESC4":  # ACL de template modificável = permissões excessivas
            signals.append(AdSignal("excessive_permissions", ef.target, ef.severity))

    for nf in ntlm or []:
        if nf.kind == "smb_signing_not_required":
            signals.append(AdSignal("smb_signing_disabled", nf.host, nf.severity))

    for sf in shadow or []:
        if sf.kind == "shadow_credentials_writable":  # gravável ⇒ shadow creds + ACL incorreta
            signals.append(AdSignal("shadow_credentials", sf.target, sf.severity))
            signals.append(AdSignal("acl_misconfig", sf.target, sf.severity))

    seen: set[tuple[str, str]] = set()
    deduped: list[AdSignal] = []
    for s in signals:
        key = (s.kind, s.target)
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped


def analyze_ad_scenarios(
    *,
    kerberos: list[KerberosFinding] | None = None,
    adcs: list[EscFinding] | None = None,
    password: list[PasswordFinding] | None = None,
    ntlm: list[NtlmFinding] | None = None,
    shadow: list[ShadowCredFinding] | None = None,
) -> list[AttackScenario]:
    """Fim a fim: analisadores → sinais → cenários priorizados."""
    return correlate_scenarios(
        to_ad_signals(kerberos=kerberos, adcs=adcs, password=password, ntlm=ntlm, shadow=shadow)
    )
