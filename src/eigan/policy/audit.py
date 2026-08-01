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
- **Sem segredo/PII em claro (P8):** todo campo textual passa pela redaction unificada
  (`ai/sanitize.redact`, §11.2) antes de ser persistido.
- **Append-only real:** o arquivo é aberto em modo append; a trilha nunca reescreve
  linhas existentes. Não há método de deleção — a preservação/backup dedicado e o
  restore com verificação de cadeia são o §27.2 (`backup_trail`/`restore_trail`).
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..ai.sanitize import redact as _redact  # ponto único de redaction (§11.2, P8)

GENESIS_HASH = "0" * 64


class AuditIntegrityError(Exception):
    """Backup/restore recusado: a cadeia de hash da trilha não está íntegra (§27.2)."""


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

    def record_purge(
        self,
        *,
        actor: str,
        target: str,
        engagement: str | None = None,
        detail: str = "",
    ) -> AuditEntry:
        """Registra um expurgo (§11.3) **na** trilha — ela grava que o expurgo ocorreu,
        sem reter o dado expurgado e sem se apagar. A trilha sobrevive ao expurgo (§27.2).
        """
        return self.append(
            "purge",
            actor=actor,
            target=target,
            metadata={"engagement": engagement or "", "detail": detail},
        )

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


# ── Preservação: backup dedicado + restore com verificação de cadeia (§27.2) ──
# A trilha tem requisito mais forte que os findings: não pode ser perdida nem reescrita.
# O backup é dedicado (não confia no backup do store) e o restore verifica a cadeia de
# hash ANTES de sobrescrever o destino — nunca troca uma trilha íntegra por um backup
# corrompido (mesmo princípio do restore do store, §27.1).


def backup_trail(trail: AuditTrail, dest: str | Path) -> AuditVerification:
    """Copia a trilha para ``dest`` e devolve a verificação da cadeia da origem.

    A cópia é fiel (preserva o append-only). O resultado informa honestamente se a
    origem estava íntegra no momento do backup (P2) — o chamador decide o que fazer com
    um backup de trilha já comprometida."""
    result = trail.verify()
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if trail.path.exists():
        shutil.copy2(trail.path, dest_path)
    else:
        dest_path.write_text("", encoding="utf-8")  # trilha vazia → backup vazio
    return result


def restore_trail(
    src: str | Path,
    dest: str | Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> AuditTrail:
    """Restaura a trilha de ``src`` para ``dest``, **verificando a cadeia antes** de
    sobrescrever. Backup com cadeia quebrada ⇒ :class:`AuditIntegrityError` e o destino
    permanece intocado. Pós-condição: a trilha restaurada verifica com sucesso."""
    src_path, dest_path = Path(src), Path(dest)
    source_check = AuditTrail(src_path, clock=clock).verify()
    if not source_check.ok:
        raise AuditIntegrityError(
            f"backup da trilha corrompido (seq {source_check.broken_seq}: "
            f"{source_check.reason}) — restore recusado, destino intacto"
        )
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_path, dest_path)
    restored = AuditTrail(dest_path, clock=clock)
    post = restored.verify()
    if not post.ok:  # defesa em profundidade — nunca deve acontecer se a origem passou
        raise AuditIntegrityError("cadeia quebrada após restore da trilha")
    return restored
