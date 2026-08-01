"""NTLM Security Assessment (TIER X.7) — implementação própria.

Avalia, a partir de configuração coletada, a exposição a NTLM relay: SMB signing não
exigido, LDAP signing não exigido, LDAP sem channel binding e NTLMv1 permitido. São
condições padrão da indústria; a implementação é original (P7) e decide só a partir do
que foi coletado (P1). Em Domain Controllers, a ausência de LDAP signing/channel binding
é especialmente grave (relay para LDAP/LDAPS do DC). Indicativo, para avaliação
autorizada (P3).
"""

from __future__ import annotations

from dataclasses import dataclass

from ...findings.schema import Severity


@dataclass(frozen=True)
class NtlmHostConfig:
    """Configuração coletada de um host relevante a NTLM/relay."""

    host: str
    smb_signing_required: bool = False
    ldap_signing_required: bool = False
    ldap_channel_binding: bool = False
    ntlmv1_allowed: bool = False
    is_domain_controller: bool = False


@dataclass(frozen=True)
class NtlmFinding:
    """Uma exposição de NTLM/relay identificada num host."""

    kind: str
    severity: Severity
    host: str
    rationale: str


def _host_findings(h: NtlmHostConfig) -> list[NtlmFinding]:
    out: list[NtlmFinding] = []
    dc = h.is_domain_controller

    if not h.smb_signing_required:
        out.append(
            NtlmFinding(
                "smb_signing_not_required",
                Severity.HIGH,
                h.host,
                "SMB signing não exigido — host é alvo de NTLM relay via SMB.",
            )
        )
    if not h.ldap_signing_required:
        out.append(
            NtlmFinding(
                "ldap_signing_not_required",
                Severity.CRITICAL if dc else Severity.HIGH,
                h.host,
                "LDAP signing não exigido"
                + (" em Domain Controller" if dc else "")
                + " — relay para LDAP.",
            )
        )
    if not h.ldap_channel_binding:
        out.append(
            NtlmFinding(
                "ldap_no_channel_binding",
                Severity.CRITICAL if dc else Severity.HIGH,
                h.host,
                "LDAP sem channel binding (EPA)"
                + (" em Domain Controller" if dc else "")
                + " — relay para LDAPS.",
            )
        )
    if h.ntlmv1_allowed:
        out.append(
            NtlmFinding(
                "ntlmv1_allowed",
                Severity.CRITICAL,
                h.host,
                "NTLMv1 permitido — autenticação fraca, quebrável e relayável.",
            )
        )
    return out


def assess_ntlm(hosts: list[NtlmHostConfig]) -> list[NtlmFinding]:
    """Avalia os hosts e devolve as exposições de NTLM, ordenadas por severidade."""
    findings: list[NtlmFinding] = []
    for host in hosts:
        findings.extend(_host_findings(host))
    findings.sort(key=lambda f: (-f.severity.rank, f.kind, f.host))
    return findings
