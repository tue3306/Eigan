"""Autorização assinável por engajamento (§18.4).

Além do consent gate inline, um engajamento profissional precisa de uma **autorização
verificável**: referência ao documento assinado, responsável, escopo, RoE (§18.1) e
**validade**. Esta autorização é assinada por HMAC-SHA256 com um segredo do operador —
**nunca versionado** (P4) — de modo que:

- adulterar qualquer campo (inclusive esticar ``expires_at``) invalida a assinatura;
- sem o segredo do operador, a autorização não pode ser forjada;
- o objeto assinado pode ser persistido com segurança (o segredo não vai junto).

A verificação, feita no início de toda ação ativa, checa **nesta ordem**: assinatura
íntegra (comparação em tempo constante — `hmac.compare_digest`), já vigente
(``now >= issued_at``) e **não expirada** (``now <= expires_at``). É domínio puro,
determinístico e trivialmente testável.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any


class AuthorizationError(Exception):
    """Autorização inválida (assinatura incorreta, ausente ou ainda não vigente)."""


class AuthorizationExpired(AuthorizationError):
    """Autorização expirada — subclasse para tratamento específico, se desejado."""


def _to_secret_bytes(secret: str | bytes) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else secret


@dataclass(frozen=True)
class Authorization:
    """Autorização de engajamento, assinável e com validade."""

    engagement: str
    document_ref: str  # referência ao documento de autorização assinado (P1)
    responsible: str  # responsável que autorizou o engajamento
    scope_digest: str  # digest do escopo autorizado
    roe_digest: str  # digest do RoE (§18.1)
    issued_at: datetime
    expires_at: datetime
    signature: str = ""  # HMAC-SHA256 hex; vazio = ainda não assinada

    def _signed_content(self) -> str:
        payload = {
            "engagement": self.engagement,
            "document_ref": self.document_ref,
            "responsible": self.responsible,
            "scope_digest": self.scope_digest,
            "roe_digest": self.roe_digest,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def compute_signature(self, secret: str | bytes) -> str:
        """HMAC-SHA256 (hex) do conteúdo canônico com o segredo do operador."""
        return hmac.new(
            _to_secret_bytes(secret), self._signed_content().encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def sign(self, secret: str | bytes) -> Authorization:
        """Devolve uma cópia assinada (o segredo nunca é armazenado no objeto)."""
        return replace(self, signature=self.compute_signature(secret))

    def is_expired(self, now: datetime) -> bool:
        return now > self.expires_at

    def verify(self, secret: str | bytes, *, now: datetime) -> None:
        """Valida assinatura, vigência e expiração; levanta em qualquer falha."""
        expected = self.compute_signature(secret)
        if not self.signature or not hmac.compare_digest(self.signature, expected):
            raise AuthorizationError("assinatura da autorização inválida ou ausente")
        if now < self.issued_at:
            raise AuthorizationError("autorização ainda não vigente")
        if now > self.expires_at:
            raise AuthorizationExpired(
                f"autorização do engajamento '{self.engagement}' expirou em "
                f"{self.expires_at.isoformat()}"
            )

    def is_valid(self, secret: str | bytes, *, now: datetime) -> bool:
        """Conveniência booleana de :meth:`verify` (não levanta)."""
        try:
            self.verify(secret, now=now)
            return True
        except AuthorizationError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "document_ref": self.document_ref,
            "responsible": self.responsible,
            "scope_digest": self.scope_digest,
            "roe_digest": self.roe_digest,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Authorization:
        return cls(
            engagement=str(data["engagement"]),
            document_ref=str(data["document_ref"]),
            responsible=str(data["responsible"]),
            scope_digest=str(data["scope_digest"]),
            roe_digest=str(data["roe_digest"]),
            issued_at=datetime.fromisoformat(str(data["issued_at"])),
            expires_at=datetime.fromisoformat(str(data["expires_at"])),
            signature=str(data.get("signature", "")),
        )
