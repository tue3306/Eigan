"""Kerberos Security Assessment (TIER X.3) — implementação própria.

Analisa contas de AD (a partir de atributos coletados numa avaliação autorizada) em busca
de exposições clássicas de Kerberos: kerberoasting (contas de serviço com SPN),
AS-REP roasting (pré-autenticação desabilitada) e delegações perigosas (unconstrained,
constrained, RBCD). As condições são conceitos padrão da indústria; a implementação e os
modelos são originais (P7) e decidem **apenas a partir dos atributos coletados** (P1).
Análise indicativa para avaliação autorizada (P3) — sinaliza a exposição, não executa
ataque.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...findings.schema import Severity


@dataclass(frozen=True)
class AdAccount:
    """Atributos coletados de uma conta de AD relevantes a Kerberos."""

    sam: str
    enabled: bool = True
    is_user: bool = True  # conta de usuário (vs. computador)
    spns: list[str] = field(default_factory=list)  # service principal names
    dont_require_preauth: bool = False  # DONT_REQ_PREAUTH → AS-REP roastable
    unconstrained_delegation: bool = False  # TRUSTED_FOR_DELEGATION
    is_domain_controller: bool = False  # DCs têm unconstrained legitimamente
    constrained_delegation_targets: list[str] = field(default_factory=list)
    rbcd_configured: bool = False  # msDS-AllowedToActOnBehalfOfOtherIdentity
    privileged: bool = False  # membro de grupo privilegiado


@dataclass(frozen=True)
class KerberosFinding:
    """Uma exposição de Kerberos identificada numa conta."""

    kind: str  # kerberoasting / asrep_roasting / unconstrained_delegation / …
    severity: Severity
    account: str
    rationale: str


def _account_findings(a: AdAccount) -> list[KerberosFinding]:
    out: list[KerberosFinding] = []
    if not a.enabled:
        return out  # conta desabilitada não é alvo de roasting/delegação

    if a.is_user and a.spns:
        out.append(
            KerberosFinding(
                "kerberoasting",
                Severity.CRITICAL if a.privileged else Severity.HIGH,
                a.sam,
                f"Conta de usuário com SPN ({len(a.spns)}) é kerberoastable"
                + (" e é privilegiada" if a.privileged else ""),
            )
        )
    if a.dont_require_preauth:
        out.append(
            KerberosFinding(
                "asrep_roasting",
                Severity.HIGH,
                a.sam,
                "Pré-autenticação Kerberos desabilitada (DONT_REQ_PREAUTH) → AS-REP roastable",
            )
        )
    if a.unconstrained_delegation and not a.is_domain_controller:
        out.append(
            KerberosFinding(
                "unconstrained_delegation",
                Severity.CRITICAL,
                a.sam,
                "Delegação irrestrita (unconstrained) em conta que não é DC — captura de TGT",
            )
        )
    if a.constrained_delegation_targets:
        out.append(
            KerberosFinding(
                "constrained_delegation",
                Severity.HIGH,
                a.sam,
                f"Delegação restrita para {len(a.constrained_delegation_targets)} serviço(s) "
                "— impersonação para os alvos configurados",
            )
        )
    if a.rbcd_configured:
        out.append(
            KerberosFinding(
                "rbcd",
                Severity.HIGH,
                a.sam,
                "Resource-Based Constrained Delegation configurada — impersonação via RBCD",
            )
        )
    return out


def assess_kerberos(accounts: list[AdAccount]) -> list[KerberosFinding]:
    """Avalia as contas e devolve as exposições de Kerberos, ordenadas por severidade."""
    findings: list[KerberosFinding] = []
    for account in accounts:
        findings.extend(_account_findings(account))
    findings.sort(key=lambda f: (-f.severity.rank, f.kind, f.account))
    return findings
