"""Versionamento de schema da persistência (§8.2): PRAGMA user_version + bordas."""

from __future__ import annotations

import sqlite3

import pytest

from eigan.findings.schema import Finding, Severity
from eigan.findings.store import _SCHEMA_VERSION, FindingStore, SchemaVersionError


def _f() -> Finding:
    return Finding(title="t", severity=Severity.LOW, affected_asset="a", source_tool="x")


def test_fresh_db_gets_current_version(tmp_path) -> None:
    store = FindingStore(str(tmp_path / "a.db"))
    version = store._conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == _SCHEMA_VERSION
    store.close()


def test_future_version_db_is_refused_not_destroyed(tmp_path) -> None:
    db = tmp_path / "future.db"
    con = sqlite3.connect(str(db))
    con.execute(f"PRAGMA user_version = {_SCHEMA_VERSION + 50}")
    con.execute("CREATE TABLE marcador(x TEXT)")
    con.execute("INSERT INTO marcador VALUES ('dado-precioso')")
    con.commit()
    con.close()
    with pytest.raises(SchemaVersionError):
        FindingStore(str(db))
    # o dado do banco futuro NÃO foi destruído
    con = sqlite3.connect(str(db))
    assert con.execute("SELECT x FROM marcador").fetchone()[0] == "dado-precioso"
    con.close()


def test_old_db_migrated_preserving_data(tmp_path) -> None:
    db = tmp_path / "old.db"
    con = sqlite3.connect(str(db))
    con.executescript(
        "CREATE TABLE scans(id INTEGER PRIMARY KEY AUTOINCREMENT, engagement TEXT NOT NULL, "
        "profile TEXT NOT NULL, targets TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT);"
        "CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, "
        "fingerprint TEXT NOT NULL, severity TEXT NOT NULL, data TEXT NOT NULL, "
        "UNIQUE(scan_id, fingerprint));"
    )
    con.execute(
        "INSERT INTO scans(engagement,profile,targets,started_at) VALUES('e','standard','[]','t0')"
    )
    con.commit()
    con.close()  # user_version fica 0 (banco antigo)

    store = FindingStore(str(db))  # abre → migra (adiciona colunas) preservando o dado
    assert store.get_scan(1) is not None  # o scan antigo continua lá
    assert store._conn.execute("PRAGMA user_version").fetchone()[0] == _SCHEMA_VERSION
    # e o schema migrado é funcional (aceita as colunas novas):
    store.set_token_usage(1, {"total": {}})
    store.close()


def test_reopen_is_idempotent(tmp_path) -> None:
    db = tmp_path / "e.db"
    s1 = FindingStore(str(db))
    sid = s1.create_scan("e", "standard", ["x"])
    s1.add_findings(sid, [_f()])
    s1.close()
    s2 = FindingStore(str(db))  # reabrir não re-migra destrutivamente
    assert len(s2.get_findings(sid)) == 1
    assert s2._conn.execute("PRAGMA user_version").fetchone()[0] == _SCHEMA_VERSION
    s2.close()
