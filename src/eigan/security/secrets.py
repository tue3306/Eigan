"""Manuseio seguro de credencial/segredo (P8; TIER X.9).

Uma credencial coletada durante um engajamento **nunca** deve ser armazenada em texto
puro, ecoada em log/trace/repr, nem persistida em claro. `SecretHandle` encapsula o valor
e o expõe apenas por `reveal()` — todo o resto (`repr`, `str`, formatação) devolve
``[REDACTED]``. A comparação usa tempo constante (`hmac.compare_digest`).

Honestidade (P1/P2): Python não permite apagar de forma garantida uma ``str`` imutável da
memória; este módulo **não finge** wipe seguro — ele **minimiza a exposição** (nunca
serializa em claro, nunca loga) e oferece `scrub()` para remover o valor de textos antes
de persistir/transmitir. A eliminação determinística de memória exigiria buffer mutável e
é registrada como limite conhecido.
"""

from __future__ import annotations

import hmac

_REDACTED = "[REDACTED]"


class SecretHandle:
    """Encapsula um segredo que nunca aparece em repr/str/log; só via ``reveal()``."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """Devolve o valor em claro — use só no ponto que precisa (ex.: autenticar)."""
        return self._value

    def matches(self, candidate: str | SecretHandle) -> bool:
        """Compara em tempo constante com um candidato (str ou outro handle)."""
        other = candidate.reveal() if isinstance(candidate, SecretHandle) else candidate
        return hmac.compare_digest(self._value, other)

    def scrub(self, text: str) -> str:
        """Remove o valor do segredo de um texto (antes de persistir/logar)."""
        if not self._value:
            return text
        return text.replace(self._value, _REDACTED)

    def is_empty(self) -> bool:
        return not self._value

    def __repr__(self) -> str:
        return f"SecretHandle({_REDACTED})"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, spec: str) -> str:
        return _REDACTED

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretHandle):
            return self.matches(other)
        return NotImplemented

    def __hash__(self) -> int:
        # Hash do valor (não expõe o valor) — permite uso em set/dict sem vazar.
        return hash(("SecretHandle", self._value))
