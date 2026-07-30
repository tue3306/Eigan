"""Testes da API + dashboard (FastAPI TestClient sobre um banco semeado)."""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from eigan.findings.schema import CVSS, Finding, RiskScore, Severity  # noqa: E402
from eigan.findings.store import FindingStore  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "api.db"
    store = FindingStore(db)
    sid = store.create_scan("lab", "external/standard", ["http://h/"])
    f = Finding(
        title="SQLi",
        severity=Severity.HIGH,
        affected_asset="http://h/app",
        source_tool="nuclei",
        cwe="CWE-89",
        attack_technique="T1190",
        cvss=CVSS(version="3.1", score=8.8),
    )
    f.risk = RiskScore(score=96.0, kev=True, kev_verified=True)
    store.add_findings(
        sid,
        [
            f,
            Finding(
                title="Porta 80", severity=Severity.INFO, affected_asset="h:80", source_tool="nmap"
            ),
        ],
    )
    store.finish_scan(sid)
    store.close()
    monkeypatch.setenv("EIGAN_DB", str(db))
    monkeypatch.setenv("EIGAN_API_TOKEN", "test-token")
    from eigan.api.app import app

    return TestClient(app, headers={"Authorization": "Bearer test-token"}), sid


def test_health_and_meta(client):
    c, _ = client
    assert c.get("/api/v1/health").json()["status"] == "ok"
    m = c.get("/api/v1/meta").json()
    assert "ai_enabled" in m and "ai_key_detected" in m


def test_tools_health_endpoint(client):
    # Saúde das ferramentas (§12): shape + contadores consistentes + status válidos.
    c, _ = client
    body = c.get("/api/v1/tools").json()
    assert body["count"] == len(body["tools"]) and body["count"] > 0
    assert sum(body["by_status"].values()) == body["count"]
    valid = {"ok", "missing", "roadmap", "degraded"}
    assert all(t["status"] in valid for t in body["tools"])
    assert body["available"] == sum(1 for t in body["tools"] if t["available"])


def test_setup_status_reports_degraded_items(client):
    c, _ = client
    s = c.get("/api/v1/setup").json()
    assert "enabled" in s["ai"] and "key_detected" in s["ai"]
    assert "available" in s["pdf"]
    assert "missing_real" in s["tools"] and "hint" in s["tools"]


def test_report_html_downloads(client):
    c, sid = client
    r = c.get(f"/api/v1/scans/{sid}/report?format=html&style=executive")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "attachment" in r.headers.get("content-disposition", "").lower()


def test_report_json_downloads(client):
    c, sid = client
    assert c.get(f"/api/v1/scans/{sid}/report?format=json").status_code == 200


def test_report_rejects_bad_format(client):
    c, sid = client
    assert c.get(f"/api/v1/scans/{sid}/report?format=xml").status_code == 400


def test_report_missing_scan_404(client):
    c, _ = client
    assert c.get("/api/v1/scans/9999/report").status_code == 404


def test_report_pdf_serves_or_degrades_to_html(client):
    c, sid = client
    r = c.get(f"/api/v1/scans/{sid}/report?format=pdf")
    assert r.status_code == 200
    # Com WeasyPrint + libs → PDF; sem elas → HTML degradado (sinalizado no header).
    if r.headers.get("X-Report-Degraded"):
        assert "text/html" in r.headers["content-type"]
    else:
        assert "application/pdf" in r.headers["content-type"]


def test_stats_and_scan_detail(client):
    c, sid = client
    stats = c.get("/api/v1/stats").json()
    assert stats["scans"] == 1 and stats["kev"] == 1
    detail = c.get(f"/api/v1/scans/{sid}").json()
    assert detail["count"] == 2 and detail["severity"]["high"] == 1


def test_findings_filter(client):
    c, sid = client
    all_f = c.get(f"/api/v1/scans/{sid}/findings").json()
    assert all_f["count"] == 2
    high = c.get(f"/api/v1/scans/{sid}/findings?severity=high").json()
    assert high["count"] == 1 and high["findings"][0]["cwe"] == "CWE-89"


def test_inventory_attack_compliance(client):
    c, sid = client
    inv = c.get(f"/api/v1/scans/{sid}/inventory").json()
    assert inv["summary"]["assets"] >= 1
    atk = c.get(f"/api/v1/scans/{sid}/attack").json()
    assert any(h["technique"] == "T1190" for h in atk["hits"])
    comp = c.get(f"/api/v1/scans/{sid}/compliance").json()
    assert comp["indicative"] is True


def test_dashboard_html(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200 and "EIGAN" in r.text


def test_scan_404(client):
    c, _ = client
    assert c.get("/api/v1/scans/9999/findings").status_code == 404


# ── autenticação da API (ADR-0014) ───────────────────────────────────────────
def test_api_requires_token(client):
    """Sem token → 401 em toda /api/v1 (exceto /health)."""
    c, sid = client
    # cliente sem o header default
    from fastapi.testclient import TestClient

    from eigan.api.app import app

    anon = TestClient(app)
    assert anon.get("/api/v1/scans").status_code == 401
    assert anon.get(f"/api/v1/scans/{sid}/findings").status_code == 401
    assert (
        anon.post("/api/v1/scans", json={"targets": ["x"], "authorized": True}).status_code == 401
    )


def test_health_is_public(client):
    from fastapi.testclient import TestClient

    from eigan.api.app import app

    anon = TestClient(app)
    r = anon.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_wrong_token_rejected(client):
    from fastapi.testclient import TestClient

    from eigan.api.app import app

    bad = TestClient(app, headers={"Authorization": "Bearer errado"})
    assert bad.get("/api/v1/scans").status_code == 401


def test_valid_token_accepted(client):
    c, _ = client
    assert c.get("/api/v1/scans").status_code == 200


def test_dashboard_injects_token_when_local(client):
    """Modo loopback: o dashboard injeta o token para o SPA (uso local sem fricção)."""
    c, _ = client
    from eigan.api.app import app

    app.state.exposed = False
    r = c.get("/")
    assert "__EIGAN_TOKEN__" in r.text


def test_dashboard_omits_token_when_exposed(client, monkeypatch):
    """Modo exposto: o dashboard NÃO injeta o token (o operador fornece)."""
    c, _ = client
    from eigan.api.app import app

    monkeypatch.setattr(app.state, "exposed", True)
    r = c.get("/")
    assert "__EIGAN_TOKEN__" not in r.text


# ── endpoints Purple / remediação (contrato HTTP) ──────────────────
def _seed_blue_scan(db_path: str, technique: str = "T1190") -> int:

    from eigan.findings.schema import Finding, Severity
    from eigan.findings.store import FindingStore

    store = FindingStore(db_path)
    sid = store.create_scan("blue", "internal/blue", ["logs"])
    store.add_findings(
        sid,
        [
            Finding(
                title="Ataque web detectado no log",
                severity=Severity.HIGH,
                affected_asset="nginx/access.log",
                source_tool="log-analysis",
                attack_technique=technique,
            )
        ],
    )
    store.finish_scan(sid)
    store.close()
    return sid


def test_purple_endpoint_correlates_red_and_blue(client):
    import os

    c, red_sid = client
    blue_sid = _seed_blue_scan(os.environ["EIGAN_DB"])
    r = c.post("/api/v1/purple", json={"scan_ids": [red_sid, blue_sid]})
    assert r.status_code == 200
    body = r.json()
    # o SQLi do Red (T1190) foi atacado E detectado pelo Blue → coberto.
    assert "T1190" in body["covered"]
    assert body["coverage_pct"] >= 0.0


def test_purple_endpoint_404_on_unknown_scan(client):
    c, _ = client
    assert c.post("/api/v1/purple", json={"scan_ids": [99999]}).status_code == 404


def test_remediation_404_on_unknown_scan(client):
    c, _ = client
    assert c.get("/api/v1/scans/99999/remediation").status_code == 404


def test_remediation_returns_cached_without_ai(client):
    import os

    from eigan.findings.store import FindingStore

    c, sid = client
    store = FindingStore(os.environ["EIGAN_DB"])
    store.set_remediation(
        sid,
        '{"items":[{"title":"Corrigir SQLi","what":"x","how":"y","priority":"P1"}],"summary":"s"}',
    )
    store.close()
    r = c.get(f"/api/v1/scans/{sid}/remediation")
    assert r.status_code == 200
    body = r.json()
    assert body["cached"] is True
    assert body["remediation"]["items"][0]["title"] == "Corrigir SQLi"


def test_blue_to_purple_integration(client):
    """Fluxo ponta a ponta: POST /blue (upload) → POST /purple com Red+Blue."""
    c, red_sid = client
    auth = "\n".join(
        [f"sshd[{i}]: Failed password for root from 198.51.100.7 port 5{i} ssh2" for i in range(8)]
    )
    b = c.post("/api/v1/blue", json={"logs": [{"name": "auth.log", "content": auth}], "ai": False})
    assert b.status_code == 202
    blue_sid = b.json()["scan_id"]
    p = c.post("/api/v1/purple", json={"scan_ids": [red_sid, blue_sid]})
    assert p.status_code == 200
    body = p.json()
    # Blue detectou força-bruta (T1110); Red não atacou T1110 → detection_only.
    assert "T1110" in body["detection_only"] or body["blue_techniques"] >= 1
