"""Backup e restauração verificados do store (§27.1): backup → destrói → restaura → compara."""

from __future__ import annotations

from pathlib import Path

import pytest

from eigan.findings.schema import Finding, Severity
from eigan.findings.store import FindingStore, restore


def _finding() -> Finding:
    return Finding(
        title="XSS", severity=Severity.HIGH, affected_asset="http://x/a", source_tool="nuclei"
    )


def test_backup_restore_roundtrip(tmp_path) -> None:
    db = tmp_path / "eigan.db"
    store = FindingStore(str(db))
    sid = store.create_scan("eng", "standard", ["example.com"])
    store.add_findings(sid, [_finding()])
    assert store.integrity_ok()
    backup = tmp_path / "backup.db"
    store.backup(backup)
    store.close()

    # destrói o banco (e sidecars WAL/SHM)
    for p in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")):
        if p.exists():
            p.unlink()
    assert not db.exists()

    # restaura e compara — os dados voltam íntegros.
    restore(backup, db)
    assert db.exists()
    restored = FindingStore(str(db))
    assert restored.get_scan(sid) is not None
    assert len(restored.get_findings(sid)) == 1
    assert restored.get_findings(sid)[0].title == "XSS"
    assert restored.integrity_ok()
    restored.close()


def test_restore_refuses_corrupt_backup(tmp_path) -> None:
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"isto nao e um banco sqlite valido " * 20)
    target = tmp_path / "target.db"
    with pytest.raises(ValueError):
        restore(bad, target)
    assert not target.exists()  # backup corrompido nunca substitui o destino


def test_restore_missing_backup_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        restore(tmp_path / "nao-existe.db", tmp_path / "target.db")
