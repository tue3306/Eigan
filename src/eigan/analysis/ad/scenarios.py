"""Correlação inteligente de sinais de AD em cenários de risco (TIER X.11).

Quando múltiplas descobertas se relacionam, o EIGAN as combina num **único cenário de
risco priorizado**, em vez de N findings soltos (evita duplicação). Cada regra descreve
uma combinação perigosa conhecida (conceitos padrão da indústria) — a implementação é
própria (P7) e só dispara com base nos sinais efetivamente coletados (P1).

Exemplos de combinação (do roadmap): Kerberoasting + conta privilegiada + política de
senha fraca; ESC1 + template vulnerável + permissões excessivas; Shadow Credentials +
ACL incorreta; NTLM Relay + SMB Signing desabilitado; Password Spraying + MFA ausente.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...findings.schema import Severity


@dataclass(frozen=True)
class AdSignal:
    """Um sinal atômico coletado/derivado (kind normalizado, alvo, severidade)."""

    kind: str
    target: str  # domínio, conta ou host ao qual o sinal se refere
    severity: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class CombinationRule:
    """Regra: quais sinais, juntos, formam um cenário — e com que prioridade."""

    name: str
    required: frozenset[str]
    severity: Severity
    description: str
    same_target: bool = False  # se True, os sinais precisam compartilhar o alvo


@dataclass(frozen=True)
class AttackScenario:
    """Cenário de risco correlacionado a partir de vários sinais."""

    name: str
    severity: Severity
    description: str
    signals: list[AdSignal] = field(default_factory=list)
    confidence: int = 0

    @property
    def targets(self) -> list[str]:
        return sorted({s.target for s in self.signals})


DEFAULT_RULES: tuple[CombinationRule, ...] = (
    CombinationRule(
        "Comprometimento de domínio via Kerberoasting",
        frozenset({"kerberoasting", "privileged_account", "weak_password_policy"}),
        Severity.CRITICAL,
        "Conta de serviço kerberoastable, privilegiada, sob política de senha fraca — "
        "cracking offline provável do TGS até credencial privilegiada.",
    ),
    CombinationRule(
        "Escalada via AD CS (ESC1)",
        frozenset({"esc1", "vulnerable_template", "excessive_permissions"}),
        Severity.CRITICAL,
        "Template vulnerável a ESC1 com permissões excessivas de enrolamento — "
        "emissão de certificado de autenticação para qualquer principal.",
    ),
    CombinationRule(
        "Persistência via Shadow Credentials",
        frozenset({"shadow_credentials", "acl_misconfig"}),
        Severity.HIGH,
        "msDS-KeyCredentialLink gravável por ACL incorreta — persistência baseada em "
        "certificado sobre o objeto alvo.",
        same_target=True,
    ),
    CombinationRule(
        "NTLM Relay",
        frozenset({"ntlm_relay", "smb_signing_disabled"}),
        Severity.HIGH,
        "Exposição a NTLM relay com SMB signing desabilitado — autenticação coagida "
        "retransmitida a um alvo sem assinatura.",
    ),
    CombinationRule(
        "Password Spraying sem MFA",
        frozenset({"password_spraying", "mfa_absent"}),
        Severity.HIGH,
        "Superfície de password spraying sem MFA — comprometimento de conta por "
        "tentativa distribuída de senha.",
    ),
)


def _confidence(n_signals: int) -> int:
    """Confiança cresce com o número de sinais corroborantes (transparente, P2)."""
    return min(100, 40 + 20 * n_signals)


def _matching_signals(rule: CombinationRule, signals: list[AdSignal]) -> list[AdSignal] | None:
    """Sinais que satisfazem a regra (um por kind exigido); None se falta algum.

    Com ``same_target``, todos os sinais precisam compartilhar o mesmo alvo."""
    if rule.same_target:
        by_target: dict[str, dict[str, AdSignal]] = {}
        for s in signals:
            if s.kind in rule.required:
                by_target.setdefault(s.target, {})[s.kind] = s
        for target in sorted(by_target):
            if rule.required <= set(by_target[target]):
                return [by_target[target][k] for k in sorted(rule.required)]
        return None
    picked: dict[str, AdSignal] = {}
    for s in signals:
        if s.kind in rule.required and s.kind not in picked:
            picked[s.kind] = s
    if rule.required <= set(picked):
        return [picked[k] for k in sorted(rule.required)]
    return None


def correlate_scenarios(
    signals: list[AdSignal], *, rules: tuple[CombinationRule, ...] = DEFAULT_RULES
) -> list[AttackScenario]:
    """Correlaciona sinais em cenários priorizados; ordenados por severidade e confiança."""
    scenarios: list[AttackScenario] = []
    for rule in rules:
        matched = _matching_signals(rule, signals)
        if matched is None:
            continue
        scenarios.append(
            AttackScenario(
                name=rule.name,
                severity=rule.severity,
                description=rule.description,
                signals=matched,
                confidence=_confidence(len(matched)),
            )
        )
    scenarios.sort(key=lambda sc: (-sc.severity.rank, -sc.confidence, sc.name))
    return scenarios
