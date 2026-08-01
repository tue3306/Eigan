"""Trilha de auditoria à prova de adulteração (§18.3).

Falha antes / passa depois: a trilha encadeada por hash detecta qualquer edição,
remoção ou reordenação de entrada; campos textuais são redigidos (P8); a cadeia
sobrevive à reabertura (append-only) e continua sequencial.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from eigan.policy.audit import GENESIS_HASH, AuditTrail


class _FakeClock:
    """Relógio determinístico: cada leitura avança 1 segundo."""

    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t = self._t + timedelta(seconds=1)
        return now


def _trail(tmp_path) -> AuditTrail:
    return AuditTrail(tmp_path / "audit.jsonl", clock=_FakeClock())


def test_genesis_prev_hash_and_chain_links(tmp_path) -> None:
    trail = _trail(tmp_path)
    e1 = trail.append("scan", actor="op", target="host-a")
    e2 = trail.append("scan", actor="op", target="host-b")
    assert e1.prev_hash == GENESIS_HASH
    assert e1.seq == 1 and e2.seq == 2
    # o prev_hash de cada entrada é o entry_hash da anterior
    assert e2.prev_hash == e1.entry_hash
    assert trail.last_hash == e2.entry_hash


def test_verify_ok_on_untampered(tmp_path) -> None:
    trail = _trail(tmp_path)
    for i in range(5):
        trail.append("action", actor="op", target=f"h{i}")
    result = trail.verify()
    assert result.ok is True
    assert result.entries == 5
    assert result.broken_seq is None


def test_verify_detects_edited_entry(tmp_path) -> None:
    trail = _trail(tmp_path)
    trail.append("scan", actor="op", target="h0")
    trail.append("scan", actor="op", target="h1")
    trail.append("scan", actor="op", target="h2")
    # Atacante edita o alvo da 2ª entrada diretamente no arquivo.
    lines = trail.path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["target"] = "h1-adulterado"
    lines[1] = json.dumps(obj, ensure_ascii=False)
    trail.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = trail.verify()
    assert result.ok is False
    assert result.broken_seq == 2  # a entrada editada é detectada


def test_verify_detects_removed_entry(tmp_path) -> None:
    trail = _trail(tmp_path)
    trail.append("scan", actor="op", target="h0")
    trail.append("scan", actor="op", target="h1")
    trail.append("scan", actor="op", target="h2")
    # Atacante remove a entrada do meio (tenta apagar um rastro).
    lines = trail.path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    trail.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = trail.verify()
    assert result.ok is False  # a cadeia quebra (seq/prev_hash não conferem)


def test_secrets_and_pii_are_redacted(tmp_path) -> None:
    trail = _trail(tmp_path)
    entry = trail.append(
        "scan",
        actor="analyst@example.com",
        target="http://api?token=SUPER_SECRET_VALUE",
        metadata={"note": "password=hunter2"},
    )
    raw = trail.path.read_text(encoding="utf-8")
    assert "SUPER_SECRET_VALUE" not in raw
    assert "hunter2" not in raw
    assert "analyst@example.com" not in raw
    assert entry.actor == "[REDACTED]"
    assert "[REDACTED]" in entry.target


def test_reopen_continues_chain(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    t1 = AuditTrail(path, clock=_FakeClock())
    e1 = t1.append("scan", actor="op", target="h0")
    # Reabre (nova instância, ex.: outro processo) e continua a cadeia.
    t2 = AuditTrail(path, clock=_FakeClock())
    assert t2.last_hash == e1.entry_hash
    assert len(t2) == 1
    e2 = t2.append("scan", actor="op", target="h1")
    assert e2.seq == 2
    assert e2.prev_hash == e1.entry_hash
    assert t2.verify().ok is True


def test_append_only_grows_by_one_line(tmp_path) -> None:
    trail = _trail(tmp_path)
    trail.append("a", actor="op", target="h0")
    n_before = len(trail.path.read_text(encoding="utf-8").splitlines())
    trail.append("b", actor="op", target="h1")
    n_after = len(trail.path.read_text(encoding="utf-8").splitlines())
    assert n_after == n_before + 1  # append nunca reescreve linhas anteriores


def test_entry_hash_is_deterministic(tmp_path) -> None:
    # Mesmo conteúdo + mesmo relógio ⇒ mesmo hash (reprodutível, §21.3).
    a = AuditTrail(tmp_path / "a.jsonl", clock=_FakeClock())
    b = AuditTrail(tmp_path / "b.jsonl", clock=_FakeClock())
    ea = a.append("scan", actor="op", target="host", authorization="doc-1")
    eb = b.append("scan", actor="op", target="host", authorization="doc-1")
    assert ea.entry_hash == eb.entry_hash


def test_empty_trail_verifies(tmp_path) -> None:
    trail = _trail(tmp_path)
    result = trail.verify()
    assert result.ok is True
    assert result.entries == 0
