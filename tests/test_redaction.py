"""Redaction unificada — ponto único reusável (§11.2, P8).

`ai.sanitize.redact` é a política única; `ai.provider.redact` e a trilha de auditoria
delegam a ela. Estes testes travam a cobertura das classes de segredo/PII e a
propriedade de ser o MESMO objeto em todas as superfícies (sem duplicação).
"""

from __future__ import annotations

from eigan.ai import provider as provider_mod
from eigan.ai.sanitize import redact
from eigan.policy import audit as audit_mod

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abc-DEF_123"
_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----"


def test_covers_all_secret_and_pii_classes() -> None:
    samples = {
        "aws": "chave AKIAABCDEFGHIJKLMNOP no log",
        "jwt": f"authz {_JWT}",
        "kv": "password: hunter2",
        "email": "contato ana@empresa.com",
        "pem": _PEM,
    }
    for label, text in samples.items():
        out = redact(text)
        assert "[REDACTED]" in out, label
    assert "hunter2" not in redact("password: hunter2")
    assert "ana@empresa.com" not in redact("ana@empresa.com")
    assert "AKIAABCDEFGHIJKLMNOP" not in redact("AKIAABCDEFGHIJKLMNOP")
    assert _JWT not in redact(_JWT)
    assert "MIIBOgIBAAJBAK" not in redact(_PEM)


def test_provider_and_audit_delegate_to_the_single_point() -> None:
    # Não há duas políticas: provider e audit apontam para o MESMO objeto de sanitize.
    assert provider_mod.redact is redact
    assert audit_mod._redact is redact


def test_redact_is_idempotent_and_total() -> None:
    once = redact("password=abc ana@x.com")
    assert redact(once) == once  # aplicar de novo não muda nada
    # nunca levanta, inclusive em entrada vazia / não-string-limpa
    assert redact("") == ""
    assert isinstance(redact("texto sem segredo"), str)


def test_no_false_positive_on_plain_text() -> None:
    plain = "servidor web Apache na porta 443 sem credenciais"
    assert redact(plain) == plain  # texto comum não é alterado
