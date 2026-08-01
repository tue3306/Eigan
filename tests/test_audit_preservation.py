"""Preservação da trilha de auditoria (§27.2).

Falha antes / passa depois: backup dedicado + restore que verifica a cadeia antes de
sobrescrever; backup corrompido é recusado (destino intacto); expurgo é registrado NA
trilha (que sobrevive); e a trilha não expõe método de deleção (append-only).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from eigan.policy.audit import (
    AuditIntegrityError,
    AuditTrail,
    backup_trail,
    restore_trail,
)


class _Clock:
    def __init__(self) -> None:
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        now = self._t
        self._t += timedelta(seconds=1)
        return now


def _make(tmp_path, name: str) -> AuditTrail:
    trail = AuditTrail(tmp_path / name, clock=_Clock())
    for i in range(3):
        trail.append("scan", actor="op", target=f"h{i}")
    return trail


def test_backup_then_restore_round_trip(tmp_path) -> None:
    trail = _make(tmp_path, "audit.jsonl")
    backup = tmp_path / "backup" / "audit.bak"
    result = backup_trail(trail, backup)
    assert result.ok is True and result.entries == 3

    # a trilha original é adulterada (atacante edita uma entrada)
    lines = trail.path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("h1", "h1-adulterado")
    trail.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert AuditTrail(trail.path).verify().ok is False

    # restaurar do backup recupera uma cadeia íntegra
    restored = restore_trail(backup, trail.path)
    check = restored.verify()
    assert check.ok is True and check.entries == 3
    targets = [e.target for e in restored.entries()]
    assert targets == ["h0", "h1", "h2"]


def test_restore_refuses_corrupt_backup_and_keeps_dest(tmp_path) -> None:
    trail = _make(tmp_path, "audit.jsonl")
    good_backup = tmp_path / "good.bak"
    backup_trail(trail, good_backup)

    # corrompe o backup
    corrupt = tmp_path / "corrupt.bak"
    lines = good_backup.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("h1", "X")
    corrupt.write_text("\n".join(lines) + "\n", encoding="utf-8")

    dest = tmp_path / "audit.jsonl"
    before = dest.read_text(encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        restore_trail(corrupt, dest)
    # o destino NÃO foi sobrescrito pelo backup corrompido
    assert dest.read_text(encoding="utf-8") == before
    assert AuditTrail(dest).verify().ok is True


def test_purge_is_recorded_in_trail_which_survives(tmp_path) -> None:
    trail = _make(tmp_path, "audit.jsonl")
    n_before = len(trail)
    entry = trail.record_purge(actor="admin", target="engajamento-x", detail="LGPD art. 18")
    assert entry.action == "purge"
    assert len(trail) == n_before + 1  # o expurgo ACRESCENTA à trilha, não a apaga
    assert trail.verify().ok is True  # a cadeia continua íntegra


def test_trail_has_no_deletion_method(tmp_path) -> None:
    trail = _make(tmp_path, "audit.jsonl")
    for forbidden in ("delete", "remove", "clear", "truncate", "purge_all", "drop"):
        assert not hasattr(trail, forbidden), forbidden


def test_backup_reports_broken_source_honestly(tmp_path) -> None:
    trail = _make(tmp_path, "audit.jsonl")
    lines = trail.path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("h1", "Y")
    trail.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = backup_trail(trail, tmp_path / "b.bak")
    assert result.ok is False  # backup não esconde que a origem já estava comprometida
