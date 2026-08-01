"""Password Security Assessment de AD (TIER X.4).

Falha antes / passa depois: política sem lockout/complexidade/comprimento fraco é
sinalizada; conta privilegiada sem MFA, inativa, senha-nunca-expira e órfã idem; conta
desabilitada não gera nada; política forte + conta saudável não geram nada; ordenação.
"""

from __future__ import annotations

from eigan.analysis.ad.password import (
    PasswordPolicy,
    PwAccount,
    assess_passwords,
)
from eigan.findings.schema import Severity


def test_weak_policy_flags_lockout_length_complexity() -> None:
    policy = PasswordPolicy(min_length=6, complexity_enabled=False, lockout_threshold=0)
    kinds = {f.kind for f in assess_passwords(policy)}
    assert "no_account_lockout" in kinds
    assert "weak_min_length" in kinds
    assert "no_complexity" in kinds


def test_strong_policy_only_flags_no_expiration_as_low() -> None:
    policy = PasswordPolicy(
        min_length=14, complexity_enabled=True, lockout_threshold=5, max_password_age_days=0
    )
    findings = assess_passwords(policy)
    assert [f.kind for f in findings] == ["password_never_expires_policy"]
    assert findings[0].severity is Severity.LOW


def test_privileged_without_mfa_is_high() -> None:
    acc = PwAccount(sam="admin", is_privileged=True, has_mfa=False)
    findings = assess_passwords(accounts=[acc])
    assert any(f.kind == "privileged_without_mfa" and f.severity is Severity.HIGH for f in findings)


def test_inactive_and_orphaned_and_never_expires() -> None:
    acc = PwAccount(
        sam="svc",
        is_privileged=True,
        has_mfa=True,
        last_logon_days=200,
        password_never_expires=True,
        orphaned=True,
    )
    kinds = {f.kind for f in assess_passwords(accounts=[acc])}
    assert kinds == {
        "inactive_account",
        "privileged_password_never_expires",
        "orphaned_account",
    }


def test_disabled_account_produces_nothing() -> None:
    acc = PwAccount(sam="old", enabled=False, is_privileged=True, has_mfa=False, orphaned=True)
    assert assess_passwords(accounts=[acc]) == []


def test_healthy_account_and_no_policy_produce_nothing() -> None:
    acc = PwAccount(sam="user", is_privileged=True, has_mfa=True, last_logon_days=1)
    assert assess_passwords(accounts=[acc]) == []


def test_sorted_by_severity() -> None:
    policy = PasswordPolicy(min_length=6, lockout_threshold=0, max_password_age_days=0)
    findings = assess_passwords(policy)
    assert findings[0].severity.rank >= findings[-1].severity.rank
    assert findings[-1].kind == "password_never_expires_policy"  # LOW por último
