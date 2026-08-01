"""Manuseio seguro de credencial (P8; TIER X.9).

Falha antes / passa depois: o segredo nunca aparece em repr/str/format/f-string; só sai
por reveal(); comparação em tempo constante; scrub remove o valor de textos; igualdade
não vaza; hash não expõe o valor.
"""

from __future__ import annotations

from eigan.security.secrets import SecretHandle

_S = "senha-super-secreta-123"


def test_never_leaks_in_repr_str_or_format() -> None:
    h = SecretHandle(_S)
    assert _S not in repr(h)
    assert _S not in str(h)
    assert _S not in f"{h}"
    assert _S not in f"credencial={h!r}"
    assert str(h) == "[REDACTED]"


def test_reveal_returns_value() -> None:
    assert SecretHandle(_S).reveal() == _S


def test_matches_constant_time_equality() -> None:
    h = SecretHandle(_S)
    assert h.matches(_S) is True
    assert h.matches("errada") is False
    assert h.matches(SecretHandle(_S)) is True


def test_scrub_removes_value_from_text() -> None:
    h = SecretHandle(_S)
    text = f"log: usuario=admin senha={_S} host=x"
    scrubbed = h.scrub(text)
    assert _S not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_equality_and_hash_do_not_leak() -> None:
    a, b = SecretHandle(_S), SecretHandle(_S)
    assert a == b
    assert a != SecretHandle("outra")
    # usável em set sem vazar; o repr do set não contém o valor
    s = {a, b}
    assert len(s) == 1
    assert _S not in repr(s)


def test_empty_secret() -> None:
    h = SecretHandle("")
    assert h.is_empty() is True
    assert h.scrub("nada a remover") == "nada a remover"
