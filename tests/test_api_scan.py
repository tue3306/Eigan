"""Testes da API de scan em tempo real (api/app.py + scan_manager.py).

Cobre a jornada da UI sem tocar CLI: recusa sem consent, início de job,
conclusão, cascade-log e streaming por WebSocket. Não depende de ferramentas
externas — o pipeline roda e conclui vazio quando nada está instalado.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGAN_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("EIGAN_API_TOKEN", "test-token")
    # EIGAN é AI-native (§3.4/ADR-0012): um provedor precisa existir para o scan
    # rodar. Uma chave de teste satisfaz o gate e o planner tenta a IA; como a
    # chamada falha (chave inválida/sem rede), o AgenticPlanner cai no substrato
    # determinístico — o scan conclui sem depender de rede.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("EIGAN_AI_PROVIDER", raising=False)
    # reimporta o app com o DB temporário e manager limpo.
    import importlib

    from eigan.api import app as app_mod
    from eigan.api.scan_manager import ScanManager
    from eigan.engine.registry import PluginRegistry

    importlib.reload(app_mod)
    # Registry vazio: os testes de API exercem o plumbing (consent, lifecycle,
    # eventos, WebSocket), não ferramentas reais. Assim o scan conclui na hora e
    # de forma determinística mesmo em hosts com nmap/naabu instalados (Kali).
    app_mod._manager = ScanManager(str(tmp_path / "api.db"), registry=PluginRegistry([]))
    return TestClient(app_mod.app, headers={"Authorization": "Bearer test-token"})


def _wait(client, job_id, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/v1/jobs/{job_id}").json()
        if s["status"] in ("completed", "failed", "cancelled"):
            return s
        time.sleep(0.05)
    raise AssertionError("job não concluiu no tempo esperado")


def test_scan_requires_authorization(client):
    r = client.post(
        "/api/v1/scans",
        json={"targets": ["10.0.0.5"], "perspective": "internal", "objective": "quick"},
    )
    assert r.status_code == 403  # consent gate preservado


def test_scan_accepts_ai_budget_field(client):
    # §2.1: o teto de IA (max_ai_tokens) é aceito e flui para o Budget do scan.
    r = client.post(
        "/api/v1/scans",
        json={
            "targets": ["example.com"],
            "perspective": "external",
            "objective": "quick",
            "authorized": True,
            "max_ai_tokens": 100,
        },
    )
    assert r.status_code == 202


def test_scan_rejects_invalid_ai_budget(client):
    # max_ai_tokens < 1 é rejeitado pela validação do modelo (422), não silenciosamente.
    r = client.post(
        "/api/v1/scans",
        json={"targets": ["example.com"], "authorized": True, "max_ai_tokens": 0},
    )
    assert r.status_code == 422


def test_scan_requires_ai_provider(client, monkeypatch):
    # AI-native (§3.4/ADR-0012): sem provedor, o scan é recusado com 428 acionável.
    for k in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "GOOGLE_API_KEY",
        "GOOGLE_MODEL",
        "OLLAMA_HOST",
        "OLLAMA_MODEL",
        "GROQ_API_KEY",
        "GROQ_MODEL",
        "OPENROUTER_API_KEY",
        "OPENROUTER_MODEL",
        "TOGETHER_API_KEY",
        "TOGETHER_MODEL",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_DEPLOYMENT",
        "EIGAN_AI_PROVIDER",
    ):
        monkeypatch.delenv(k, raising=False)
    r = client.post(
        "/api/v1/scans",
        json={
            "targets": ["10.0.0.5"],
            "perspective": "internal",
            "objective": "quick",
            "authorized": True,
        },
    )
    assert r.status_code == 428  # Precondition Required: falta provedor de IA
    assert "provedor de IA" in r.json()["detail"]


def test_scan_lifecycle_and_cascade_log(client):
    r = client.post(
        "/api/v1/scans",
        json={
            "targets": ["10.0.0.5"],
            "perspective": "internal",
            "objective": "quick",
            "authorized": True,
        },
    )
    assert r.status_code == 202
    job_id = r.json()["id"]
    assert r.json()["status"] in ("queued", "running")

    final = _wait(client, job_id)
    assert final["status"] == "completed"

    prog = client.get(f"/api/v1/jobs/{job_id}/progress").json()
    types = [e["type"] for e in prog["events"]]
    # registry vazio (hermético): sem fases, mas o ciclo completo é emitido.
    assert "analysis_complete" in types
    assert types[-1] == "scan_status"

    casc = client.get(f"/api/v1/jobs/{job_id}/cascade-log").json()
    assert "cascade_log" in casc  # existe mesmo que vazio (sem ferramentas)

    # EIGAN: a timeline de raciocínio do agente é transmitida (eventos `log`);
    # o passo "planned" registra o plano inicial — sem caixa-preta.
    logs = [e for e in prog["events"] if e["type"] == "log"]
    assert logs, "o agente deve transmitir o raciocínio (eventos log)"
    assert any("[plano" in e.get("message", "") for e in logs)


def test_scan_uses_ai_planner_even_when_use_ai_false(client, monkeypatch):
    """§3.4 (AI-native, tudo-ou-nada): mesmo com ``use_ai=False`` um scan REAL usa a
    IA para PLANEJAR — não existe caminho determinístico que produza um scan sem a
    IA. ``use_ai`` controla só as narrativas por IA, nunca o planejador. Regressão:
    antes, ``use_ai=False`` fazia o engine rodar o DeterministicPlanner direto (a IA
    nem era chamada), furando o inegociável §3.4."""
    import eigan.ai.provider as prov

    calls: list[str] = []

    class _FakeAI:
        def available(self) -> bool:
            return True

        def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
            calls.append("plan")
            return '{"capabilities": []}'  # plano válido (vazio) — sem rede

    # start() e _run() fazem `from ..ai.provider import require_provider` em tempo de
    # chamada; monkeypatch no módulo atinge ambos.
    monkeypatch.setattr(prov, "require_provider", lambda: _FakeAI())
    r = client.post(
        "/api/v1/scans",
        json={
            "targets": ["10.0.0.5"],
            "perspective": "internal",
            "objective": "quick",
            "authorized": True,
            "use_ai": False,
        },
    )
    assert r.status_code == 202
    _wait(client, r.json()["id"])
    assert calls, "o planner deve chamar a IA mesmo com use_ai=False (§3.4)"


def test_invalid_perspective_is_rejected(client):
    r = client.post(
        "/api/v1/scans",
        json={"targets": ["10.0.0.5"], "perspective": "lunar", "authorized": True},
    )
    assert r.status_code == 400


def test_websocket_streams_until_end(client):
    job = client.post(
        "/api/v1/scans",
        json={
            "targets": ["10.0.0.5"],
            "perspective": "internal",
            "objective": "quick",
            "authorized": True,
        },
    ).json()
    types = []
    with client.websocket_connect(f"/ws/scans/{job['id']}/progress?token=test-token") as ws:
        for _ in range(60):
            e = ws.receive_json()
            types.append(e["type"])
            if e["type"] == "stream_end":
                break
    assert types[-1] == "stream_end"
    assert "scan_status" in types


def test_findings_and_assets_endpoints(client):
    # sem scan ainda: endpoints respondem vazio, não 500.
    f = client.get("/api/v1/findings").json()
    assert f["count"] == 0 and f["findings"] == []
    a = client.get("/api/v1/assets").json()
    assert a["assets"] == []


def test_unknown_job_is_404(client):
    assert client.get("/api/v1/jobs/job-999").status_code == 404


def test_blue_endpoint_analyzes_uploaded_logs(client):
    # ADR-0020: o cliente ENVIA o conteúdo do log (não um caminho no servidor).
    auth = "\n".join(
        [f"sshd[{i}]: Failed password for root from 203.0.113.9 port 5{i} ssh2" for i in range(8)]
    )
    r = client.post(
        "/api/v1/blue",
        json={"logs": [{"name": "auth.log", "content": auth}], "ai": False},
    )
    assert r.status_code == 202
    body = r.json()
    assert body["detections"] >= 1 and body["scan_id"] is not None
    assert any("T1110" in (f.get("attack_technique") or "") for f in body["findings"])


def test_blue_endpoint_requires_token(client):
    from fastapi.testclient import TestClient

    from eigan.api.app import app

    anon = TestClient(app)
    r = anon.post("/api/v1/blue", json={"logs": [{"content": "x"}], "ai": False})
    assert r.status_code == 401  # auth obrigatória (ADR-0014)
