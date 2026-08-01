"""Autorização assinável por engajamento (§18.4).

Falha antes / passa depois: a autorização assinada valida com o segredo correto dentro
da validade; adulteração invalida a assinatura; segredo errado falha; expiração e
não-vigência são respeitadas; o segredo nunca é armazenado no objeto.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from eigan.policy.authorization import (
    Authorization,
    AuthorizationError,
    AuthorizationExpired,
)

_SECRET = "segredo-do-operador-nao-versionado"
_ISSUED = datetime(2026, 8, 1, tzinfo=timezone.utc)
_EXPIRES = _ISSUED + timedelta(days=7)
_DURING = _ISSUED + timedelta(days=1)


def _auth(**kw) -> Authorization:
    base = dict(
        engagement="cliente-x",
        document_ref="AUTORIZACAO-2026-042",
        responsible="responsavel",
        scope_digest="a" * 64,
        roe_digest="b" * 64,
        issued_at=_ISSUED,
        expires_at=_EXPIRES,
    )
    base.update(kw)
    return Authorization(**base)


def test_signed_authorization_verifies_within_validity() -> None:
    auth = _auth().sign(_SECRET)
    auth.verify(_SECRET, now=_DURING)  # não levanta
    assert auth.is_valid(_SECRET, now=_DURING) is True


def test_unsigned_authorization_is_rejected() -> None:
    with pytest.raises(AuthorizationError):
        _auth().verify(_SECRET, now=_DURING)


def test_wrong_secret_fails() -> None:
    auth = _auth().sign(_SECRET)
    with pytest.raises(AuthorizationError):
        auth.verify("segredo-errado", now=_DURING)


def test_tampering_expiry_invalidates_signature() -> None:
    auth = _auth().sign(_SECRET)
    # Atacante estica a validade DEPOIS de assinar (sem re-assinar).
    forged = replace(auth, expires_at=_EXPIRES + timedelta(days=365))
    with pytest.raises(AuthorizationError):
        forged.verify(_SECRET, now=_DURING)


def test_expired_authorization_raises_expired() -> None:
    auth = _auth().sign(_SECRET)
    with pytest.raises(AuthorizationExpired):
        auth.verify(_SECRET, now=_EXPIRES + timedelta(seconds=1))
    assert auth.is_expired(_EXPIRES + timedelta(seconds=1)) is True


def test_not_yet_valid_authorization_raises() -> None:
    auth = _auth().sign(_SECRET)
    with pytest.raises(AuthorizationError):
        auth.verify(_SECRET, now=_ISSUED - timedelta(seconds=1))


def test_signature_is_deterministic() -> None:
    assert _auth().sign(_SECRET).signature == _auth().sign(_SECRET).signature


def test_secret_is_never_stored_on_object() -> None:
    auth = _auth().sign(_SECRET)
    assert _SECRET not in repr(auth)
    assert _SECRET not in str(auth.to_dict())


def test_dict_round_trip_preserves_verifiability() -> None:
    auth = _auth().sign(_SECRET)
    restored = Authorization.from_dict(auth.to_dict())
    assert restored == auth
    restored.verify(_SECRET, now=_DURING)  # continua verificável após serializar
