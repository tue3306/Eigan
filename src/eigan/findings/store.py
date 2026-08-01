"""Persistência de scans e findings.

Usa ``sqlite3`` da stdlib (default) mantendo a interface desacoplada do banco
(Repository Pattern, CLAUDE.md §6/§9): trocar por Postgres significa fornecer
outra implementação de :class:`FindingStore`, sem tocar em domínio/aplicação.

Nota: o schema `Finding` é o contrato; aqui apenas serializamos/deserializamos.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .schema import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement TEXT NOT NULL,
    profile TEXT NOT NULL,
    targets TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE(scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""

#: Número de schema atual (§8.2). Sobe quando uma migração numerada é adicionada.
_SCHEMA_VERSION = 1


class SchemaVersionError(RuntimeError):
    """O banco é de uma versão de schema **mais nova** que a suportada — recusado
    para NÃO destruir dados (§8.2). Atualize o EIGAN para abrir este banco."""


def restore(backup_path: str | Path, target_path: str | Path) -> None:
    """Restaura um backup para ``target_path`` (§27.1), verificando a integridade do
    backup ANTES de sobrescrever — um backup corrompido nunca substitui dados bons. O
    store de destino deve estar **fechado**. Remove sidecars WAL/SHM antigos do destino.
    """
    import shutil

    backup_path, target_path = Path(backup_path), Path(target_path)
    if not backup_path.exists():
        raise FileNotFoundError(f"backup não encontrado: {backup_path}")
    con = sqlite3.connect(str(backup_path))
    try:
        row = con.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"backup ilegível/corrompido: {exc} — restauração recusada") from exc
    finally:
        con.close()
    if not row or row[0] != "ok":
        raise ValueError(f"backup corrompido (integrity_check={row}) — restauração recusada")
    shutil.copyfile(backup_path, target_path)
    for suffix in ("-wal", "-shm"):  # estado antigo do destino não pode contaminar
        side = Path(str(target_path) + suffix)
        if side.exists():
            side.unlink()


class FindingStore:
    def __init__(self, db_path: str | Path | None = "eigan.db") -> None:
        # Defesa: um `db_path` nulo/vazio (ex.: caller que esqueceu de resolver o
        # default) NÃO deve virar silenciosamente um banco chamado "None"/"" —
        # isso já produziu um arquivo-fantasma no passado. Cai no default seguro.
        self._path = str(db_path) if db_path else "eigan.db"
        # timeout generoso + WAL: suporta MÚLTIPLOS scans simultâneos (cada job roda
        # em sua thread com sua própria conexão) sem "database is locked". WAL deixa
        # leitores (dashboard/API) não bloquearem o escritor (o scan em andamento).
        self._conn = sqlite3.connect(self._path, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        if self._path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._check_and_migrate()
        self._conn.commit()

    def _check_and_migrate(self) -> None:
        """Versionamento de schema (§8.2) via ``PRAGMA user_version``.

        Banco de versão **futura** é RECUSADO (nunca destruído); versões antigas são
        migradas ao schema atual (idempotente) e o novo número é gravado. Banco vazio
        (fresh) recebe a versão atual."""
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if version > _SCHEMA_VERSION:
            raise SchemaVersionError(
                f"banco na versão de schema {version}, mais nova que a suportada "
                f"({_SCHEMA_VERSION}). Recusado para não destruir dados — atualize o EIGAN."
            )
        self._migrate()
        self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")  # int confiável, sem injeção

    def _migrate(self) -> None:
        """Migrações idempotentes de schema (ADD COLUMN se faltar). Mantém bancos
        antigos compatíveis sem apagar dados."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(scans)")}
        if "ai_analysis" not in cols:
            # Análise da IA (Analysis Engine) persistida junto do scan.
            self._conn.execute("ALTER TABLE scans ADD COLUMN ai_analysis TEXT")
        if "ai_remediation" not in cols:
            # Plano de remediação da IA (o que arrumar + como) — JSON estruturado.
            self._conn.execute("ALTER TABLE scans ADD COLUMN ai_remediation TEXT")
        if "status" not in cols:
            # Ciclo de vida do scan (ADR-0017): running|completed|failed|cancelled|
            # partial. Bancos antigos (com finished_at) viram 'completed' se já
            # terminaram, senão 'running'. Persistência incremental depende disso.
            self._conn.execute("ALTER TABLE scans ADD COLUMN status TEXT")
            self._conn.execute(
                "UPDATE scans SET status = CASE WHEN finished_at IS NOT NULL "
                "THEN 'completed' ELSE 'running' END WHERE status IS NULL"
            )
        if "executed_capabilities" not in cols:
            # Capacidades já executadas (JSON) — base para retomada de scan parcial.
            self._conn.execute("ALTER TABLE scans ADD COLUMN executed_capabilities TEXT")
        if "token_usage" not in cols:
            # Uso de tokens da IA no scan (JSON) — observabilidade §22, ADR-0025.
            self._conn.execute("ALTER TABLE scans ADD COLUMN token_usage TEXT")

    def create_scan(self, engagement: str, profile: str, targets: list[str]) -> int:
        cur = self._conn.execute(
            "INSERT INTO scans(engagement, profile, targets, started_at, status) "
            "VALUES (?,?,?,?,'running')",
            (engagement, profile, json.dumps(targets), datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()
        assert cur.lastrowid is not None  # garantido após INSERT bem-sucedido
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: str = "completed") -> None:
        """Marca o scan como terminado com um ``status`` do ciclo de vida (ADR-0017)."""
        self._conn.execute(
            "UPDATE scans SET finished_at=?, status=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), status, scan_id),
        )
        self._conn.commit()

    def set_status(self, scan_id: int, status: str) -> None:
        """Atualiza só o status (ex.: 'running'→'partial') sem marcar finished_at."""
        self._conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
        self._conn.commit()

    def set_executed_capabilities(self, scan_id: int, capabilities: list[str]) -> None:
        """Persiste as capacidades já executadas (para retomada de scan parcial)."""
        self._conn.execute(
            "UPDATE scans SET executed_capabilities=? WHERE id=?",
            (json.dumps(sorted(capabilities)), scan_id),
        )
        self._conn.commit()

    def get_executed_capabilities(self, scan_id: int) -> list[str]:
        row = self._conn.execute(
            "SELECT executed_capabilities FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
        if not row or not row["executed_capabilities"]:
            return []
        try:
            return list(json.loads(row["executed_capabilities"]))
        except (json.JSONDecodeError, TypeError):
            return []

    def set_token_usage(self, scan_id: int, usage: dict) -> None:
        """Persiste o uso de tokens da IA no scan (JSON) — observabilidade (ADR-0025)."""
        self._conn.execute(
            "UPDATE scans SET token_usage=? WHERE id=?", (json.dumps(usage), scan_id)
        )
        self._conn.commit()

    def get_token_usage(self, scan_id: int) -> dict | None:
        row = self._conn.execute("SELECT token_usage FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row or not row["token_usage"]:
            return None
        try:
            return dict(json.loads(row["token_usage"]))
        except (json.JSONDecodeError, TypeError):
            return None

    def running_scans(self) -> list[dict]:
        """Scans não terminados (status 'running'/'partial') — candidatos a retomada."""
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE status IN ('running','partial') ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def set_analysis(self, scan_id: int, analysis: str) -> None:
        """Grava a análise da IA (Analysis Engine) do scan."""
        self._conn.execute("UPDATE scans SET ai_analysis=? WHERE id=?", (analysis, scan_id))
        self._conn.commit()

    def get_analysis(self, scan_id: int) -> str | None:
        row = self._conn.execute("SELECT ai_analysis FROM scans WHERE id=?", (scan_id,)).fetchone()
        return row["ai_analysis"] if row and row["ai_analysis"] else None

    def set_remediation(self, scan_id: int, remediation_json: str) -> None:
        """Grava o plano de remediação da IA (JSON estruturado) do scan."""
        self._conn.execute(
            "UPDATE scans SET ai_remediation=? WHERE id=?", (remediation_json, scan_id)
        )
        self._conn.commit()

    def get_remediation(self, scan_id: int) -> str | None:
        row = self._conn.execute(
            "SELECT ai_remediation FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
        return row["ai_remediation"] if row and row["ai_remediation"] else None

    def add_findings(self, scan_id: int, findings: Iterable[Finding]) -> int:
        n = 0
        for f in findings:
            # UPSERT no UNIQUE(scan_id, fingerprint): a persistência incremental
            # (por onda) grava o finding cru; o _finalize regrava a versão dedupada
            # e pontuada (risco), que deve SOBRESCREVER a incremental — por isso
            # ON CONFLICT DO UPDATE em vez de OR IGNORE (ADR-0017).
            self._conn.execute(
                "INSERT INTO findings(scan_id, fingerprint, severity, data) VALUES (?,?,?,?) "
                "ON CONFLICT(scan_id, fingerprint) DO UPDATE SET "
                "severity=excluded.severity, data=excluded.data",
                (scan_id, f.fingerprint, f.severity.value, f.model_dump_json()),
            )
            n += 1
        self._conn.commit()
        return n

    def get_findings(self, scan_id: int) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT data FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
        ).fetchall()
        return [Finding.model_validate_json(r["data"]) for r in rows]

    def integrity_ok(self) -> bool:
        """``PRAGMA integrity_check`` — True se o banco está íntegro (§27.1)."""
        row = self._conn.execute("PRAGMA integrity_check").fetchone()
        return bool(row) and row[0] == "ok"

    def backup(self, dest: str | Path) -> None:
        """Backup **consistente** para ``dest`` via API de backup online do SQLite
        (respeita o WAL; não precisa parar o scan). O arquivo resultante é
        autocontido. Restaure com :func:`restore`."""
        dst = sqlite3.connect(str(dest))
        try:
            self._conn.backup(dst)
        finally:
            dst.close()  # fecha (o context manager só commitaria, não fecharia)

    def get_scan(self, scan_id: int) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def find_previous_scan(self, scan_id: int) -> Optional[int]:
        """Scan concluído mais recente ANTES de ``scan_id`` com algum alvo em comum.

        Base determinística da memória entre execuções (Pilar 2 / ADR-0008): dá o
        baseline natural para o diff. Retorna ``None`` se for a primeira vez que o
        alvo é escaneado.
        """
        cur = self.get_scan(scan_id)
        if cur is None:
            return None
        try:
            cur_targets = set(json.loads(cur["targets"]))
        except (json.JSONDecodeError, TypeError):
            return None
        rows = self._conn.execute(
            "SELECT id, targets FROM scans WHERE id < ? AND finished_at IS NOT NULL "
            "ORDER BY id DESC",
            (scan_id,),
        ).fetchall()
        for row in rows:
            try:
                prev_targets = set(json.loads(row["targets"]))
            except (json.JSONDecodeError, TypeError):
                continue
            if cur_targets & prev_targets:
                return int(row["id"])
        return None

    def close(self) -> None:
        self._conn.close()
