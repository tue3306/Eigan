"""Trilha de auditoria à prova de adulteração (§18.3).

Um pentest autorizado precisa de **prova defensável** de que o engajamento seguiu as
regras: quem fez o quê, contra qual alvo, quando, sob qual autorização/RoE, com qual
modelo de IA. Esta trilha é **append-only e encadeada por hash**: cada entrada inclui
o hash da anterior, então adulterar (editar/remover/reordenar) qualquer entrada quebra
a cadeia e é detectável por ``verify()``.

Decisões de design:

- **Encadeamento:** ``entry_hash = sha256(conteúdo_canônico)`` onde o conteúdo inclui
  ``prev_hash``. A entrada gênese usa ``prev_hash`` de 64 zeros. Editar a entrada N
  muda seu ``entry_hash``, que é o ``prev_hash`` de N+1 — a divergência se propaga.
- **Determinismo:** o relógio é injetável (``clock``) para testes reproduzíveis; a
  serialização canônica ordena as chaves. Mesmo conteúdo ⇒ mesmo hash.
- **Sem segredo/PII em claro (P8):** todo campo textual passa por redaction antes de
  ser persistido. A redaction plena é unificada no §11.2; aqui aplicamos o piso
  conservador (segredos ``chave=valor`` e e-mail).
- **Append-only real:** o arquivo é aberto em modo append; a trilha nunca reescreve
  linhas existentes. A preservação/restore da trilha é o §27.2.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

GENESIS_HASH = "0" * 64

# Redaction-piso (§18.3/P8) — o §11.2 unifica a política completa em ai/sanitize.
_SECRET_KV = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|authorization|bearer)\b\s*[:=]\s*\S+"
)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def _redact(text: str) -> str:
    """Remove segredo/PII de um campo textual antes de persistir (P8)."""
    out = _SECRET_KV.sub(r"\1=[REDACTED]", text)
    return _EMAIL.sub("[REDACTED]", out)


class AuditEntry(BaseModel):
    """Uma entrada imutável da trilha, assinada por hash encadeado."""

    model_config = ConfigDict(frozen=True)

    seq: int
    timestamp: str
    actor: str
    action: str
    target: str
    authorization: str | None = None
    roe: str | None = None
    ai_model: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str

    def _signed_content(self) -> str:
        """Serialização canônica dos campos assinados (tudo menos ``entry_hash``)."""
        payload = self.model_dump(exclude={"entry_hash"})
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def compute_hash(self) -> str:
        """Recalcula o ``entry_hash`` a partir do conteúdo assinado."""
        return hashlib.sha256(self._signed_content().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditVerification:
    """Resultado de ``AuditTrail.verify``."""

    ok: bool
    entries: int
    broken_seq: int | None = None  # 1º seq cuja cadeia/hash não confere; None se íntegra
    reason: str | None = None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class AuditTrail:
    """Trilha append-only encadeada por hash, persistida como JSONL.

    Cada ``append`` lê o hash da última entrada, compõe a nova (com ``prev_hash``),
    calcula o ``entry_hash`` e grava uma linha JSON. ``verify`` relê tudo e confirma
    que a cadeia está íntegra.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        redactor: Callable[[str], str] | None = None,
    ) -> None:
        self.path = Path(path)
        self._clock = clock or _now_utc
        self._redact = redactor or _redact
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash, self._count = self._load_tail()

    def _load_tail(self) -> tuple[str, int]:
        """Recupera (hash da última entrada, nº de entradas) reabrindo a trilha."""
        if not self.path.exists():
            return GENESIS_HASH, 0
        last_hash, count = GENESIS_HASH, 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                count += 1
                last_hash = json.loads(line)["entry_hash"]
        return last_hash, count

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def __len__(self) -> int:
        return self._count

    def append(
        self,
        action: str,
        *,
        actor: str,
        target: str,
        authorization: str | None = None,
        roe: str | None = None,
        ai_model: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> AuditEntry:
        """Registra uma ação na trilha e devolve a entrada gravada (redigida)."""
        seq = self._count + 1
        meta = {self._redact(k): self._redact(v) for k, v in (metadata or {}).items()}
        base = AuditEntry(
            seq=seq,
            timestamp=self._clock().isoformat(),
            actor=self._redact(actor),
            action=self._redact(action),
            target=self._redact(target),
            authorization=self._redact(authorization) if authorization is not None else None,
            roe=self._redact(roe) if roe is not None else None,
            ai_model=ai_model,
            metadata=meta,
            prev_hash=self._last_hash,
            entry_hash="",  # placeholder; recalculado abaixo
        )
        entry = base.model_copy(update={"entry_hash": base.compute_hash()})
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.model_dump(), ensure_ascii=False) + "\n")
        self._last_hash = entry.entry_hash
        self._count = seq
        return entry

    def entries(self) -> Iterator[AuditEntry]:
        """Itera as entradas na ordem de gravação."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield AuditEntry.model_validate_json(line)

    def verify(self) -> AuditVerification:
        """Reprocessa a cadeia inteira e detecta qualquer adulteração.

        Verifica, para cada entrada: (1) o ``entry_hash`` bate com o conteúdo,
        (2) o ``prev_hash`` bate com o ``entry_hash`` da anterior, (3) ``seq`` é
        sequencial a partir de 1. Qualquer falha ⇒ ``ok=False`` com o ``broken_seq``.
        """
        prev = GENESIS_HASH
        count = 0
        for expected_seq, entry in enumerate(self.entries(), start=1):
            count = expected_seq
            if entry.seq != expected_seq:
                return AuditVerification(False, count, entry.seq, "seq fora de ordem")
            if entry.prev_hash != prev:
                return AuditVerification(False, count, entry.seq, "prev_hash quebrado")
            if entry.entry_hash != entry.compute_hash():
                return AuditVerification(False, count, entry.seq, "entry_hash adulterado")
            prev = entry.entry_hash
        return AuditVerification(True, count)
