"""RBAC com menor privilégio (§20.1).

A autenticação por **token único** (ADR-0014) dá poder total a quem o possui e não
responde "quem disparou este scan?". Numa equipe de segurança — ou numa consultoria
com vários clientes — isso é bloqueador de adoção corporativa e fere o princípio de
menor privilégio. Este módulo adiciona **papéis** e **tokens com escopo**, sem quebrar
o fluxo de token único existente (que segue como o papel de fato ``admin`` local).

Papéis (menor privilégio por padrão):

- **admin** — configura, gerencia engajamentos (todas as permissões);
- **operator** — dispara/para scans no escopo autorizado, aprova ações (HITL), lê e
  gera relatório;
- **analyst** — marca finding (FP/risco aceito), comenta, gera relatório, lê;
- **auditor** — lê findings e a trilha; **não executa nada**.

É domínio puro (sem I/O de rede), trivialmente testável. O token nunca é armazenado em
claro — o registry guarda apenas o SHA-256 (P4/P8). Expiração e revogação são de 1ª
classe. A atribuição de identidade em cada ação (§20.2) usa o ``subject`` do principal.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class AccessDenied(Exception):
    """Ação negada: sem permissão, fora do engajamento, token expirado ou revogado."""


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class Permission(str, Enum):
    CONFIGURE = "configure"  # alterar configuração do sistema
    MANAGE_ENGAGEMENT = "manage_engagement"  # criar/editar engajamentos
    RUN_SCAN = "run_scan"  # disparar ação ativa
    STOP_SCAN = "stop_scan"  # kill switch (§18.2)
    APPROVE_ACTION = "approve_action"  # aprovar ação de alto impacto (HITL §19.5)
    MARK_FINDING = "mark_finding"  # FP/risco aceito (§13.1)
    GENERATE_REPORT = "generate_report"
    READ_FINDINGS = "read_findings"
    READ_AUDIT = "read_audit"  # ler a trilha de auditoria (§18.3)


_ALL: frozenset[Permission] = frozenset(Permission)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: _ALL,
    Role.OPERATOR: frozenset(
        {
            Permission.RUN_SCAN,
            Permission.STOP_SCAN,
            Permission.APPROVE_ACTION,
            Permission.GENERATE_REPORT,
            Permission.READ_FINDINGS,
            Permission.READ_AUDIT,
        }
    ),
    Role.ANALYST: frozenset(
        {
            Permission.MARK_FINDING,
            Permission.GENERATE_REPORT,
            Permission.READ_FINDINGS,
        }
    ),
    Role.AUDITOR: frozenset({Permission.READ_FINDINGS, Permission.READ_AUDIT}),
}


@dataclass(frozen=True)
class Principal:
    """Identidade autenticada: quem é, qual papel, quais engajamentos, validade."""

    subject: str
    role: Role
    engagements: frozenset[str] = field(default_factory=frozenset)  # vazio = todos
    issued_at: datetime | None = None
    expires_at: datetime | None = None

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now > self.expires_at

    def can(self, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS.get(self.role, frozenset())

    def in_engagement(self, engagement: str) -> bool:
        return not self.engagements or engagement in self.engagements


def authorize(
    principal: Principal,
    permission: Permission,
    *,
    engagement: str | None = None,
    now: datetime,
) -> None:
    """Autoriza (ou nega) uma ação para o principal. Levanta :class:`AccessDenied`.

    Ordem: expiração → permissão do papel → escopo de engajamento."""
    if principal.is_expired(now):
        raise AccessDenied(f"token de '{principal.subject}' expirado")
    if not principal.can(permission):
        raise AccessDenied(
            f"papel '{principal.role.value}' não tem a permissão '{permission.value}'"
        )
    if engagement is not None and not principal.in_engagement(engagement):
        raise AccessDenied(f"'{principal.subject}' fora do engajamento '{engagement}'")


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class TokenRegistry:
    """Vincula tokens a principals sem guardar o token em claro (só o SHA-256)."""

    def __init__(self) -> None:
        self._by_hash: dict[str, Principal] = {}
        self._revoked: set[str] = set()

    def issue(self, secret: str, principal: Principal) -> None:
        """Registra um token (só o hash) para um principal."""
        self._by_hash[_hash(secret)] = principal

    def revoke(self, secret: str) -> None:
        """Revoga um token — passa a ser negado mesmo se não expirou."""
        self._revoked.add(_hash(secret))

    def resolve(self, provided: str | None, *, now: datetime) -> Principal:
        """Resolve um token ao principal; levanta :class:`AccessDenied` se inválido,
        revogado ou expirado. O lookup é por digest (o token nunca é comparado em
        claro; sha256 é resistente a pré-imagem)."""
        if not provided:
            raise AccessDenied("token ausente")
        digest = _hash(provided)
        if digest in self._revoked:
            raise AccessDenied("token revogado")
        principal = self._by_hash.get(digest)
        if principal is None:
            raise AccessDenied("token desconhecido")
        if principal.is_expired(now):
            raise AccessDenied(f"token de '{principal.subject}' expirado")
        return principal
