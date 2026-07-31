"""Cache de resposta de IA por conteúdo (§2.3).

A mesma ``(prompt, modelo, versão)`` → **reusa** a resposta, sem pagar a chamada de
novo: na mesma execução (dedup dentro do scan) e, opcionalmente, **entre scans**
(persistência em disco). É economia transparente, não redução de qualidade — o
mesmo conteúdo produziria a mesma análise.

Segurança (P8): **nunca guarda segredo/PII em claro**. A CHAVE é um hash SHA-256 (o
prompt não é armazenado em texto), e o VALOR é a resposta **já redigida** para
provedores externos (o chamador aplica :func:`redact` antes de gravar). Ollama local
não exige redaction (nada sai da máquina).

Invalidação correta: o conteúdo do prompt e o modelo entram na chave (mudou o
prompt/modelo → chave diferente → miss). :data:`CACHE_VERSION` permite forçar a
invalidação mesmo com o mesmo conteúdo (ex.: mudança de contrato de parsing) — está
ligada ao versionamento/regressão de prompt do §2.7.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

#: Versão do protocolo de prompts/parsing de IA. Bump = invalida todo o cache.
CACHE_VERSION = "1"

_WS = re.compile(r"\s+")


def _normalize(text: str) -> str:
    """Colapsa espaços para uma chave estável (reformatação trivial não gera miss)."""
    return _WS.sub(" ", text.strip())


class ResponseCache:
    """Cache de resposta endereçado por conteúdo. In-memory por padrão; persistente
    (JSON) quando um ``path`` é dado. Best-effort: falha de I/O nunca derruba a IA."""

    def __init__(self, *, version: str = CACHE_VERSION, path: str | Path | None = None) -> None:
        self._version = version
        self._mem: dict[str, str] = {}
        self._path = Path(path) if path else None
        if self._path is not None:
            self._load()

    def key(self, *, system: str, user: str, model: str, json_mode: bool = False) -> str:
        blob = "\x00".join(
            (
                self._version,
                model,
                "json" if json_mode else "text",
                _normalize(system),
                _normalize(user),
            )
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def get(self, key: str) -> str | None:
        return self._mem.get(key)

    def put(self, key: str, response: str) -> None:
        self._mem[key] = response
        if self._path is not None:
            self._persist()

    def __len__(self) -> int:
        return len(self._mem)

    # ── persistência best-effort ────────────────────────────────────────────────
    def _load(self) -> None:
        assert self._path is not None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            self._mem = {str(k): str(v) for k, v in data.items()}

    def _persist(self) -> None:
        assert self._path is not None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._mem), encoding="utf-8")
        except OSError:
            pass
