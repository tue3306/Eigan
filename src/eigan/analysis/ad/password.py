"""Password Security Assessment de AD (TIER X.4) — implementação própria.

Avalia, a partir de dados coletados numa avaliação autorizada, a **política de senha** do
domínio e atributos de conta que ampliam a superfície de comprometimento por senha:
ausência de bloqueio de conta (habilita password spraying), complexidade/comprimento
fracos, contas privilegiadas sem MFA, contas inativas/órfãs e senhas que nunca expiram.
As condições são padrão da indústria; a implementação é original (P7) e decide só a
partir do que foi coletado (P1). Análise indicativa para avaliação autorizada (P3).

Nota: este módulo **não** faz spraying — apenas mede a superfície. A execução de spraying
autorizado, com limites para não travar contas, é validação ativa gated (fora daqui).
"""

from __future__ import annotations

from dataclasses import dataclass

from ...findings.schema import Severity

# Piso de comprimento abaixo do qual a política é considerada fraca (heurística declarada).
_WEAK_MIN_LENGTH = 8
_INACTIVE_DAYS = 90


@dataclass(frozen=True)
class PasswordPolicy:
    """Política de senha do domínio (atributos coletados)."""

    min_length: int = 0
    complexity_enabled: bool = False
    lockout_threshold: int = 0  # 0 = sem bloqueio → spraying sem risco de travar conta
    max_password_age_days: int = 0  # 0 = nunca expira
    history_size: int = 0


@dataclass(frozen=True)
class PwAccount:
    """Atributos de conta relevantes a exposição por senha."""

    sam: str
    enabled: bool = True
    is_privileged: bool = False
    has_mfa: bool = False
    last_logon_days: int = 0  # dias desde o último logon
    password_never_expires: bool = False
    orphaned: bool = False  # sem dono/gestor identificável


@dataclass(frozen=True)
class PasswordFinding:
    """Uma exposição relacionada a senha (política ou conta)."""

    kind: str
    severity: Severity
    target: str
    rationale: str


def _policy_findings(policy: PasswordPolicy) -> list[PasswordFinding]:
    out: list[PasswordFinding] = []
    if policy.lockout_threshold == 0:
        out.append(
            PasswordFinding(
                "no_account_lockout",
                Severity.HIGH,
                "domain",
                "Sem bloqueio de conta (lockout threshold = 0) — habilita password spraying.",
            )
        )
    if policy.min_length < _WEAK_MIN_LENGTH:
        out.append(
            PasswordFinding(
                "weak_min_length",
                Severity.HIGH,
                "domain",
                f"Comprimento mínimo de senha {policy.min_length} < {_WEAK_MIN_LENGTH}.",
            )
        )
    if not policy.complexity_enabled:
        out.append(
            PasswordFinding(
                "no_complexity",
                Severity.MEDIUM,
                "domain",
                "Requisito de complexidade de senha desabilitado.",
            )
        )
    if policy.max_password_age_days == 0:
        out.append(
            PasswordFinding(
                "password_never_expires_policy",
                Severity.LOW,
                "domain",
                "Política sem expiração de senha (idade máxima = 0).",
            )
        )
    return out


def _account_findings(a: PwAccount) -> list[PasswordFinding]:
    out: list[PasswordFinding] = []
    if not a.enabled:
        return out
    if a.is_privileged and not a.has_mfa:
        out.append(
            PasswordFinding(
                "privileged_without_mfa",
                Severity.HIGH,
                a.sam,
                "Conta privilegiada sem MFA.",
            )
        )
    if a.last_logon_days > _INACTIVE_DAYS:
        out.append(
            PasswordFinding(
                "inactive_account",
                Severity.MEDIUM,
                a.sam,
                f"Conta habilitada inativa há {a.last_logon_days} dias (> {_INACTIVE_DAYS}).",
            )
        )
    if a.is_privileged and a.password_never_expires:
        out.append(
            PasswordFinding(
                "privileged_password_never_expires",
                Severity.MEDIUM,
                a.sam,
                "Conta privilegiada com senha que nunca expira.",
            )
        )
    if a.orphaned:
        out.append(
            PasswordFinding(
                "orphaned_account",
                Severity.LOW,
                a.sam,
                "Conta órfã (sem dono/gestor identificável).",
            )
        )
    return out


def assess_passwords(
    policy: PasswordPolicy | None = None, accounts: list[PwAccount] | None = None
) -> list[PasswordFinding]:
    """Avalia política e contas; devolve as exposições, ordenadas por severidade."""
    findings: list[PasswordFinding] = []
    if policy is not None:
        findings.extend(_policy_findings(policy))
    for account in accounts or []:
        findings.extend(_account_findings(account))
    findings.sort(key=lambda f: (-f.severity.rank, f.kind, f.target))
    return findings
