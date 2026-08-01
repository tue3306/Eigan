"""RBAC com menor privilégio (§20.1).

Falha antes / passa depois: cada papel só faz o que precisa (matriz de permissões),
o escopo por engajamento é respeitado, tokens expiram e são revogáveis, e o token
nunca é guardado em claro (só o SHA-256).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from eigan.security.rbac import (
    AccessDenied,
    Permission,
    Principal,
    Role,
    TokenRegistry,
    authorize,
)

_NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _p(role: Role, **kw) -> Principal:
    return Principal(subject=f"user-{role.value}", role=role, **kw)


def test_auditor_reads_but_never_executes() -> None:
    auditor = _p(Role.AUDITOR)
    authorize(auditor, Permission.READ_FINDINGS, now=_NOW)  # ok
    authorize(auditor, Permission.READ_AUDIT, now=_NOW)  # ok
    with pytest.raises(AccessDenied):
        authorize(auditor, Permission.RUN_SCAN, now=_NOW)
    with pytest.raises(AccessDenied):
        authorize(auditor, Permission.MARK_FINDING, now=_NOW)


def test_operator_runs_but_does_not_configure() -> None:
    operator = _p(Role.OPERATOR)
    authorize(operator, Permission.RUN_SCAN, now=_NOW)
    authorize(operator, Permission.STOP_SCAN, now=_NOW)
    authorize(operator, Permission.APPROVE_ACTION, now=_NOW)
    with pytest.raises(AccessDenied):
        authorize(operator, Permission.CONFIGURE, now=_NOW)


def test_analyst_marks_but_does_not_run() -> None:
    analyst = _p(Role.ANALYST)
    authorize(analyst, Permission.MARK_FINDING, now=_NOW)
    authorize(analyst, Permission.GENERATE_REPORT, now=_NOW)
    with pytest.raises(AccessDenied):
        authorize(analyst, Permission.RUN_SCAN, now=_NOW)


def test_admin_can_everything() -> None:
    admin = _p(Role.ADMIN)
    for perm in Permission:
        authorize(admin, perm, now=_NOW)  # nenhuma levanta


def test_engagement_scope_is_enforced() -> None:
    scoped = _p(Role.OPERATOR, engagements=frozenset({"cliente-a"}))
    authorize(scoped, Permission.RUN_SCAN, engagement="cliente-a", now=_NOW)
    with pytest.raises(AccessDenied):
        authorize(scoped, Permission.RUN_SCAN, engagement="cliente-b", now=_NOW)
    # engajamento vazio = todos
    allall = _p(Role.OPERATOR)
    authorize(allall, Permission.RUN_SCAN, engagement="qualquer", now=_NOW)


def test_expired_principal_is_denied() -> None:
    expired = _p(Role.ADMIN, expires_at=_NOW - timedelta(seconds=1))
    with pytest.raises(AccessDenied):
        authorize(expired, Permission.READ_FINDINGS, now=_NOW)


def test_registry_resolves_and_revokes() -> None:
    reg = TokenRegistry()
    principal = _p(Role.OPERATOR, engagements=frozenset({"e1"}))
    reg.issue("token-secreto", principal)
    assert reg.resolve("token-secreto", now=_NOW) == principal
    with pytest.raises(AccessDenied):
        reg.resolve("token-errado", now=_NOW)  # desconhecido
    reg.revoke("token-secreto")
    with pytest.raises(AccessDenied):
        reg.resolve("token-secreto", now=_NOW)  # revogado


def test_registry_denies_expired_token() -> None:
    reg = TokenRegistry()
    reg.issue("t", _p(Role.AUDITOR, expires_at=_NOW - timedelta(seconds=1)))
    with pytest.raises(AccessDenied):
        reg.resolve("t", now=_NOW)


def test_registry_denies_missing_token() -> None:
    reg = TokenRegistry()
    with pytest.raises(AccessDenied):
        reg.resolve(None, now=_NOW)
    with pytest.raises(AccessDenied):
        reg.resolve("", now=_NOW)


def test_token_is_never_stored_in_cleartext() -> None:
    reg = TokenRegistry()
    reg.issue("super-secreto", _p(Role.ADMIN))
    # o token em claro não aparece em nenhuma estrutura interna
    assert "super-secreto" not in str(reg._by_hash)
    assert "super-secreto" not in str(vars(reg))
