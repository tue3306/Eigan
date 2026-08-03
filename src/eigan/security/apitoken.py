"""Token de API do EIGAN — autentica a API/dashboard (ADR-0014, §2/§4/§5).

A API dirige scans ativos e expõe findings (que podem conter segredos). Sem
autenticação, quem alcançasse a porta transformaria a máquina do operador numa
plataforma de ataque e leria tudo. Este módulo provê o **token compartilhado**:

- ``EIGAN_API_TOKEN`` no ambiente vence (12-fator; ideal para CI/Docker).
- Senão, um token é **gerado na 1ª necessidade** (``secrets.token_urlsafe``) e
  gravado em ``~/.config/eigan/api_token`` com ``chmod 600`` — nunca commitado,
  nunca ecoado.

A comparação usa ``secrets.compare_digest`` (tempo constante). O *bind* seguro
(loopback por padrão) e a injeção do token no dashboard só em modo não-exposto
ficam na API (``api/app.py``) e no ``serve`` (``cli``).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .onboarding import config_dir

_ENV = "EIGAN_API_TOKEN"
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}


def token_file() -> Path:
    return config_dir() / "api_token"


def current_token() -> str | None:
    """Token configurado (env vence o arquivo), SEM criar nada. ``None`` se não há."""
    env = (os.getenv(_ENV) or "").strip()
    if env:
        return env
    p = token_file()
    if p.is_file():
        try:
            tok = p.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return tok or None
    return None


def load_or_create_token() -> str:
    """Retorna o token, **gerando e persistindo** um se ainda não existir.

    Idempotente: chamadas seguintes leem o mesmo valor. O arquivo é gravado com
    permissão restrita (só o dono lê)."""
    existing = current_token()
    if existing:
        return existing
    tok = secrets.token_urlsafe(32)
    p = token_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tok, encoding="utf-8")
    try:
        os.chmod(p, 0o600)  # segredo: só o dono lê
    except OSError:
        pass
    return tok


def token_matches(provided: str | None) -> bool:
    """Compara ``provided`` com o token esperado em tempo constante."""
    if not provided:
        return False
    expected = load_or_create_token()
    # ``compare_digest`` levanta TypeError em ``str`` com qualquer caractere
    # não-ASCII. O token do cliente pode conter isso (header latin-1 ou
    # ``?token=caf%C3%A9``); comparar em bytes garante 401 (False), não um 500.
    return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def is_loopback(host: str | None) -> bool:
    """O host (endereço de bind ou peer) é loopback (mesma máquina)?"""
    if not host:
        return False
    return host.strip().lower() in _LOOPBACK
