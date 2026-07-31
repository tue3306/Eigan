"""API FastAPI (REST versionado + dashboard) — §G.

Exposição HTTP dos casos de uso e das análises (inventário, ATT&CK, conformidade).
REST versionado desde o início (`/api/v1`). O dashboard web consome esta API;
nenhuma regra de negócio vive no frontend. O widget de IA só é sinalizado quando
há um provedor funcional (degrada honestamente sem chave).
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..ai.provider import AIProviderRequired, default_provider
from ..analysis.attack import map_attack
from ..analysis.compliance import assess_compliance
from ..analysis.inventory import build_inventory, summarize
from ..analysis.validation import Validator
from ..findings.schema import Finding, Severity
from ..findings.store import FindingStore
from ..security import apitoken
from .scan_manager import ScanManager

if TYPE_CHECKING:
    from ..engine.registry import PluginRegistry

app = FastAPI(
    title="EIGAN API",
    version=__version__,
    description="Plataforma modular de operações de segurança (uso autorizado).",
)

# Modo de exposição (ADR-0014): False = bind loopback (mesma máquina), o dashboard
# recebe o token injetado para uso local sem fricção. True = exposto na rede
# (0.0.0.0 via `serve --expose`/Docker); o dashboard NÃO injeta o token (o operador
# fornece EIGAN_API_TOKEN). Setado pelo `serve`; default lê o ambiente.
app.state.exposed = os.getenv("EIGAN_EXPOSE", "").strip().lower() in {"1", "true", "yes"}

_AI_ENV = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_HOST")
_TOOL_VERSION = __version__

# Rotas públicas (sem token): health e o próprio dashboard/estáticos. Todo o resto
# de /api/v1 e o WebSocket exigem o token (ADR-0014).
_PUBLIC_API_PATHS = frozenset({"/api/v1/health"})


def _extract_token(request: Request) -> str | None:
    """Token do request: header Authorization: Bearer, X-EIGAN-Token, ou ?token=.

    O query param existe para downloads/navegações que não setam header (ex.: o
    link de relatório) e para o WebSocket — aceitável num alvo local."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    header = request.headers.get("x-eigan-token")
    if header:
        return header.strip()
    return request.query_params.get("token")


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    """Exige o token do EIGAN em todo /api/v1 (exceto /health). §2/§4/ADR-0014."""
    path = request.url.path
    if path.startswith("/api/v1") and path not in _PUBLIC_API_PATHS:
        if not apitoken.token_matches(_extract_token(request)):
            return JSONResponse(
                {"detail": "não autorizado: forneça o token do EIGAN (Authorization: Bearer …)"},
                status_code=401,
            )
    return await call_next(request)


def _db_path() -> str:
    return os.getenv("EIGAN_DB", "eigan.db")


def _store() -> FindingStore:
    return FindingStore(_db_path())


# Gerente de scans em background (um por processo). Alimenta a UI em tempo real.
_manager: ScanManager | None = None


def manager() -> ScanManager:
    global _manager
    if _manager is None:
        _manager = ScanManager(_db_path())
    return _manager


# Registry de plugins cacheado por processo — a descoberta é cara para cada request.
_registry: "PluginRegistry | None" = None


def plugin_registry() -> "PluginRegistry":
    global _registry
    if _registry is None:
        from ..engine.registry import PluginRegistry

        _registry = PluginRegistry.discover()
    return _registry


def _findings_or_404(store: FindingStore, scan_id: int) -> list[Finding]:
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    return store.get_findings(scan_id)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


# ── meta / saúde ────────────────────────────────────────────────────────────
class HealthOut(BaseModel):
    status: str
    version: str


@app.get("/api/v1/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(status="ok", version=_TOOL_VERSION)


@app.get("/api/v1/tools")
def tools_health() -> dict:
    """Saúde das ferramentas (contrato ToolAdapter §12): ok/missing/roadmap/degraded.

    Alimenta o painel de saúde da plataforma (§19). Verificável — a disponibilidade
    vem de ``shutil.which``, sem versão fabricada (§2)."""
    healths = plugin_registry().health_report()
    by_status: dict[str, int] = {}
    for h in healths:
        by_status[h.status] = by_status.get(h.status, 0) + 1
    return {
        "count": len(healths),
        "available": sum(1 for h in healths if h.available),
        "by_status": by_status,
        "tools": [h.as_dict() for h in healths],
    }


@app.get("/api/v1/meta")
def meta() -> dict:
    """Sinaliza estado da IA (para o widget) e versão. ``ai_enabled`` = provedor
    FUNCIONAL; ``ai_key_detected`` = chave no ambiente (mesmo sem provedor pronto).
    Expõe também provedor/modelo/nível ativos — a UI mostra qual IA está comandando."""
    return {
        "tool_version": _TOOL_VERSION,
        "ai_enabled": default_provider() is not None,
        "ai_key_detected": any(os.getenv(k) for k in _AI_ENV),
        **_active_ai_meta(),
    }


def _active_ai_meta() -> dict:
    """Provedor/modelo/nível de IA ativos (para exibição — nunca a chave)."""
    from ..ai.provider import PROVIDERS, current_tier, default_provider

    prov = default_provider()
    if prov is None:
        return {"ai_provider": None, "ai_model": None, "ai_tier": current_tier()}
    # descobre o spec ativo pelo nome da classe do provedor construído
    label, model = None, getattr(prov, "_model", None)
    for spec in PROVIDERS.values():
        if isinstance(prov, spec.provider_cls):
            label = spec.label
            break
    return {"ai_provider": label, "ai_model": model, "ai_tier": current_tier()}


@app.get("/api/v1/setup")
def setup_status() -> dict:
    """Estado do ambiente para o onboarding visual: o que falta e como resolver.
    A IA é **obrigatória** (AI-native); PDF/ferramentas degradam graciosamente."""
    from ..cli import doctor as doctor_mod

    report = doctor_mod.gather()
    missing = [t.name for t in report.tools if not t.roadmap and not t.available]
    return {
        "ai": {
            "enabled": default_provider() is not None,
            "required": True,  # AI-native (ADR-0012): sem provedor, o scan é recusado
            "key_detected": any(os.getenv(k) for k in _AI_ENV),
            "hint": "Configure um provedor: EIGAN_AI_PROVIDER + chave (ou Ollama local, offline). "
            "Sem provedor o scan é recusado. Ver docs/ai-providers.md.",
        },
        "pdf": {
            "available": report.pdf_available,
            "detail": report.pdf_detail,
        },
        "tools": {
            "available": report.tools_available,
            "total": len(report.tools),
            "missing_real": missing,
            "hint": "python3 eigan.py --with-tools  (ou eigan doctor --install)",
        },
    }


# ── scans ───────────────────────────────────────────────────────────────────
@app.get("/api/v1/scans")
def list_scans() -> list[dict]:
    return _store().list_scans()


@app.get("/api/v1/stats")
def stats() -> dict:
    """Números agregados para a visão geral do dashboard."""
    store = _store()
    scans = store.list_scans()
    latest = scans[0]["id"] if scans else None
    findings = store.get_findings(latest) if latest else []
    return {
        "scans": len(scans),
        "latest_scan": latest,
        "findings": len(findings),
        "severity": _severity_counts(findings),
        "kev": sum(1 for f in findings if f.risk and f.risk.kev),
    }


@app.get("/api/v1/scans/{scan_id}")
def scan_detail(scan_id: int) -> dict:
    store = _store()
    meta_ = store.get_scan(scan_id)
    if not meta_:
        raise HTTPException(404, "scan não encontrado")
    findings = store.get_findings(scan_id)
    return {
        "scan": meta_,
        "count": len(findings),
        "severity": _severity_counts(findings),
        # Uso de tokens da IA no scan (observabilidade §22, ADR-0025), estruturado.
        "token_usage": store.get_token_usage(scan_id),
        # Validação (§16): quantas findings validadas + distribuição de confiança.
        "validation": Validator().summarize(findings).as_dict(),
    }


@app.get("/api/v1/scans/{scan_id}/findings")
def scan_findings(scan_id: int, severity: str | None = Query(default=None)) -> dict:
    store = _store()
    findings = _findings_or_404(store, scan_id)
    if severity:
        findings = [f for f in findings if f.severity.value == severity.lower()]
    return {
        "count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


@app.get("/api/v1/scans/{scan_id}/inventory")
def scan_inventory(scan_id: int) -> dict:
    findings = _findings_or_404(_store(), scan_id)
    inv = build_inventory(findings)
    return {"summary": summarize(inv), "assets": [asdict(a) for a in inv]}


@app.get("/api/v1/scans/{scan_id}/attack")
def scan_attack(scan_id: int) -> dict:
    findings = _findings_or_404(_store(), scan_id)
    return asdict(map_attack(findings))


@app.get("/api/v1/scans/{scan_id}/compliance")
def scan_compliance(scan_id: int) -> dict:
    findings = _findings_or_404(_store(), scan_id)
    return asdict(assess_compliance(findings))


# ── conversa com a IA + análise (Conversation Engine) ────────────────────────
class ChatRequest(BaseModel):
    """Pergunta do operador sobre um scan + histórico opcional da conversa."""

    question: str = Field(min_length=1)
    history: list[dict] = Field(default_factory=list)


def _scan_context(store: FindingStore, scan_id: int) -> str:
    from ..ai.context import build_scan_context

    meta_ = store.get_scan(scan_id)
    if not meta_:
        raise HTTPException(404, "scan não encontrado")
    findings = store.get_findings(scan_id)
    import json as _json

    targets = _json.loads(meta_.get("targets") or "[]")
    return build_scan_context(
        findings,
        engagement=meta_.get("engagement", ""),
        targets=targets,
        profile=meta_.get("profile", ""),
    )


def _ai_or_http(fn):
    """Executa ``fn`` mapeando a ausência de provedor de IA para HTTP 428."""
    try:
        return fn()
    except AIProviderRequired as exc:
        raise HTTPException(428, str(exc)) from exc


@app.post("/api/v1/scans/{scan_id}/chat")
def scan_chat(scan_id: int, req: ChatRequest) -> dict:
    """A IA responde uma pergunta sobre o scan (grounded nos findings)."""
    from ..ai.conversation import answer_question

    context = _scan_context(_store(), scan_id)
    answer = _ai_or_http(lambda: answer_question(context, req.question, history=req.history))
    return {"answer": answer}


def _generate_analysis(store: FindingStore, scan_id: int) -> str:
    """Gera a análise da IA e persiste. Propaga AIProviderRequired (→ 428)."""
    from ..ai.conversation import analyze

    text = analyze(_scan_context(store, scan_id)).strip()
    if text:
        store.set_analysis(scan_id, text)
    return text


@app.get("/api/v1/scans/{scan_id}/analysis")
def get_scan_analysis(scan_id: int) -> dict:
    """Análise da IA do scan (resumo, riscos, correlações, próximos passos).

    Retorna a análise **automática** gerada no fim do scan; se ainda não houver
    (scan antigo ou falha no finalize), gera sob demanda e persiste."""
    store = _store()
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    stored = store.get_analysis(scan_id)
    if stored:
        return {"analysis": stored, "cached": True}
    return {"analysis": _ai_or_http(lambda: _generate_analysis(store, scan_id)), "cached": False}


@app.post("/api/v1/scans/{scan_id}/analysis")
def regen_scan_analysis(scan_id: int) -> dict:
    """Regera a análise da IA do scan (sobrescreve a armazenada)."""
    store = _store()
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    return {"analysis": _ai_or_http(lambda: _generate_analysis(store, scan_id)), "cached": False}


def _remediation_dict(store: FindingStore, scan_id: int) -> dict:
    """Gera (ou regenera) o plano de remediação e devolve como dict serializável."""
    import json as _json

    from ..ai.remediation import plan_to_json
    from ..analysis.engine import remediate_scan

    meta_ = store.get_scan(scan_id)
    assert meta_ is not None  # chamador valida antes
    findings = store.get_findings(scan_id)
    targets = _json.loads(meta_.get("targets") or "[]")
    plan = remediate_scan(
        findings,
        engagement=meta_.get("engagement", ""),
        targets=targets,
        profile=meta_.get("profile", ""),
    )
    if not plan.is_empty():
        store.set_remediation(scan_id, plan_to_json(plan))
    return plan.model_dump()


@app.get("/api/v1/scans/{scan_id}/remediation")
def get_scan_remediation(scan_id: int) -> dict:
    """Plano de remediação da IA (o que arrumar + como, priorizado).

    Retorna o plano **automático** gerado ao fim do scan; se ainda não houver,
    gera sob demanda e persiste (grounded nos findings; §3.1)."""
    from ..ai.remediation import plan_from_json

    store = _store()
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    stored = plan_from_json(store.get_remediation(scan_id))
    if stored is not None:
        return {"remediation": stored.model_dump(), "cached": True}
    return {"remediation": _ai_or_http(lambda: _remediation_dict(store, scan_id)), "cached": False}


@app.post("/api/v1/scans/{scan_id}/remediation")
def regen_scan_remediation(scan_id: int) -> dict:
    """Regera o plano de remediação da IA (sobrescreve o armazenado)."""
    store = _store()
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    return {"remediation": _ai_or_http(lambda: _remediation_dict(store, scan_id)), "cached": False}


# ── merge/correlação entre scans (ex.: scans simultâneos) ────────────────────
class MergeRequest(BaseModel):
    """IDs de scans a correlacionar num relatório unificado (>= 2)."""

    scan_ids: list[int] = Field(min_length=2)


def _validate_scan_ids(store: FindingStore, scan_ids: list[int]) -> None:
    for sid in scan_ids:
        if not store.get_scan(sid):
            raise HTTPException(404, f"scan {sid} não encontrado")


@app.post("/api/v1/scans/merge")
def merge_scans_endpoint(req: MergeRequest) -> dict:
    """Correlaciona vários scans: findings deduplicados entre eles, contagem por
    severidade e por scan — a superfície unificada de alvos escaneados em paralelo."""
    from ..analysis.merge import merge_summary

    store = _store()
    _validate_scan_ids(store, req.scan_ids)
    return merge_summary(store, req.scan_ids)


@app.post("/api/v1/scans/merge/analysis")
def merge_analysis_endpoint(req: MergeRequest) -> dict:
    """Análise da IA sobre a superfície UNIFICADA (correlaciona os scans de uma vez)."""
    from ..ai.conversation import analyze
    from ..analysis.merge import merge_context

    store = _store()
    _validate_scan_ids(store, req.scan_ids)
    ctx = merge_context(store, req.scan_ids)
    return {"analysis": _ai_or_http(lambda: analyze(ctx))}


# ── Purple: correlação ataque×detecção ───────────────────────────────────────
class PurpleRequest(BaseModel):
    """Scans a correlacionar (Red + Blue). ``ai`` pede a narrativa dos gaps."""

    scan_ids: list[int] = Field(min_length=1)
    ai: bool = False


def _detection_tools() -> frozenset[str]:
    """Ferramentas Blue (detecção) conhecidas pelo registry + defaults."""
    from ..analysis.purple import DEFAULT_DETECTION_TOOLS
    from ..capability import Category
    from ..engine.registry import PluginRegistry

    tools = set(DEFAULT_DETECTION_TOOLS)
    try:
        reg = PluginRegistry.discover()
        tools |= {s.name for s in reg.all() if s.metadata.category == Category.BLUE}
    except Exception:  # noqa: BLE001 — registry indisponível não quebra a correlação
        pass
    return frozenset(tools)


@app.post("/api/v1/purple")
def purple_endpoint(req: PurpleRequest) -> dict:
    """Correlação Purple: técnicas ATT&CK atacadas (Red) × detectadas (Blue).

    Devolve a matriz de cobertura, os PONTOS CEGOS (atacado sem detecção) e o %
    de cobertura. Com ``ai=true``, inclui a narrativa da IA priorizando os gaps."""
    from ..ai.conversation import purple_analysis
    from ..analysis.purple import correlate_findings, purple_context

    store = _store()
    _validate_scan_ids(store, req.scan_ids)
    findings: list[Finding] = []
    for sid in req.scan_ids:
        findings.extend(store.get_findings(sid))
    report = correlate_findings(findings, detection_tools=_detection_tools())
    out = asdict(report)
    if req.ai:
        out["ai_narrative"] = _ai_or_http(lambda: purple_analysis(purple_context(report)))
    return out


class BlueLogItem(BaseModel):
    """Um arquivo de log ENVIADO pelo cliente (conteúdo, não caminho no servidor)."""

    name: str = "log"
    content: str = Field(min_length=1, max_length=8_000_000)  # teto de 8 MB por arquivo


class BlueRequest(BaseModel):
    logs: list[BlueLogItem] = Field(min_length=1, max_length=20)
    ai: bool = True


@app.post("/api/v1/blue", status_code=202)
def blue_endpoint(req: BlueRequest) -> dict:
    """Análise defensiva (Blue) de LOGS enviados pelo cliente (upload por conteúdo).

    SEGURANÇA (§4/§5/ADR-0020): o cliente envia o CONTEÚDO do log, não um caminho —
    a API **nunca** lê o filesystem do servidor por caminho arbitrário (sem path
    traversal / leitura de arquivo local). O conteúdo é gravado num diretório
    temporário isolado, analisado e apagado."""
    import shutil
    import tempfile
    from pathlib import Path as _Path

    from ..ai.provider import AIProviderRequired, require_provider
    from ..engine.blue import run_log_analysis
    from ..engine.feeds import FeedCache
    from ..engine.risk import RiskScorer

    try:
        provider = require_provider() if req.ai else None
    except AIProviderRequired as exc:
        raise HTTPException(428, str(exc)) from exc

    tmpdir = tempfile.mkdtemp(prefix="eigan-blue-")
    try:
        paths: list[str] = []
        for i, item in enumerate(req.logs):
            # nome saneado: só o basename, nunca componentes de caminho do cliente.
            safe = _Path(item.name or f"log{i}").name or f"log{i}"
            p = _Path(tmpdir) / f"{i}_{safe}"
            p.write_text(item.content, encoding="utf-8", errors="replace")
            paths.append(str(p))
        store = _store()
        risk = RiskScorer(FeedCache.load(), online=False)
        try:
            report = run_log_analysis(paths, store=store, risk=risk, provider=provider)
        finally:
            store.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)  # nunca deixa log do cliente no disco

    return {
        "scan_id": report.scan_id,
        "detections": len(report.findings),
        "sources": len(report.sources),
        "ai_analysis": bool(report.analysis),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "attack_technique": f.attack_technique,
                "affected_asset": f.affected_asset,
            }
            for f in report.findings
        ],
    }


@app.post("/api/v1/jobs/{job_id}/chat")
def job_chat(job_id: str, req: ChatRequest) -> dict:
    """Chat sobre um scan EM ANDAMENTO — usa as descobertas emitidas até agora."""
    from ..ai.context import build_scan_context
    from ..ai.conversation import answer_question

    job = _job_or_404(job_id)
    findings = []
    for ev_ in job.events:
        if ev_.get("type") == "discovery" and ev_.get("finding"):
            try:
                findings.append(Finding.model_validate(ev_["finding"]))
            except Exception:  # noqa: BLE001 — evento malformado nunca quebra o chat
                continue
    context = build_scan_context(
        findings, engagement=", ".join(job.targets), targets=job.targets, profile=job.profile
    )
    answer = _ai_or_http(lambda: answer_question(context, req.question, history=req.history))
    return {"answer": answer, "status": job.status, "findings_so_far": len(findings)}


_REPORT_MEDIA = {
    "pdf": "application/pdf",
    "html": "text/html",
    "md": "text/markdown",
    "json": "application/json",
    "csv": "text/csv",
    "sarif": "application/json",
}


@app.get("/api/v1/scans/{scan_id}/report")
def scan_report(
    scan_id: int,
    fmt: str = Query("html", alias="format"),
    style: str = Query("executive"),
    ai: bool = Query(False),
    classification: str = Query("confidential"),
    show_sensitive: bool = Query(False),
) -> FileResponse:
    """Gera e devolve o relatório para download. PDF degrada para HTML (§13).

    ``classification`` (public|internal|confidential|restricted) e
    ``show_sensitive`` (desliga o mascaramento de segredos) espelham a CLI."""
    from ..cli.reporting import write_report
    from ..cli.session import feeds_meta
    from ..engine.feeds import FeedCache

    store = _store()
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    fmt = fmt.lower()
    if fmt not in _REPORT_MEDIA:
        raise HTTPException(400, f"formato inválido: {fmt}")
    if style not in ("technical", "executive"):
        style = "executive"

    import tempfile

    fmeta = feeds_meta(FeedCache.load())
    tmp = Path(tempfile.gettempdir())
    headers: dict[str, str] = {}
    try:
        path, _ = write_report(
            store,
            scan_id,
            fmt=fmt,
            style=style,
            out=str(tmp / f"eigan_scan{scan_id}_{style}.{fmt}"),
            use_ai=ai,
            feeds_meta=fmeta,
            classification=classification,
            show_sensitive=show_sensitive,
        )
    except RuntimeError as exc:  # PDF indisponível → HTML equivalente (§13)
        if fmt != "pdf":
            raise HTTPException(500, f"falha ao gerar relatório: {exc}") from exc
        fmt = "html"
        headers["X-Report-Degraded"] = "pdf->html"
        path, _ = write_report(
            store,
            scan_id,
            fmt="html",
            style=style,
            out=str(tmp / f"eigan_scan{scan_id}_{style}.html"),
            use_ai=ai,
            feeds_meta=fmeta,
            classification=classification,
            show_sensitive=show_sensitive,
        )
    return FileResponse(
        str(path), media_type=_REPORT_MEDIA[fmt], filename=path.name, headers=headers
    )


# ── findings / assets globais (visão da UI, sobre o último scan) ─────────────
def _latest_scan_id(store: FindingStore) -> int | None:
    scans = store.list_scans()
    return scans[0]["id"] if scans else None


@app.get("/api/v1/findings")
def findings_global(
    severity: str | None = Query(default=None),
    scan_id: int | None = Query(default=None),
) -> dict:
    """Findings filtrados. Sem ``scan_id``, usa o último scan (visão do dashboard)."""
    store = _store()
    sid = scan_id if scan_id is not None else _latest_scan_id(store)
    findings = store.get_findings(sid) if sid is not None else []
    if severity:
        findings = [f for f in findings if f.severity.value == severity.lower()]
    return {
        "scan_id": sid,
        "count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


@app.get("/api/v1/assets")
def assets_global(scan_id: int | None = Query(default=None)) -> dict:
    """Inventário de ativos do último scan (ou de ``scan_id``), ordenado por risco."""
    store = _store()
    sid = scan_id if scan_id is not None else _latest_scan_id(store)
    findings = store.get_findings(sid) if sid is not None else []
    inv = build_inventory(findings)
    inv.sort(key=lambda a: a.max_risk, reverse=True)
    return {"scan_id": sid, "summary": summarize(inv), "assets": [asdict(a) for a in inv]}


# ── scans em tempo real (jobs) ───────────────────────────────────────────────
class ScanRequest(BaseModel):
    """Corpo do POST /scans vindo do wizard. ``authorized`` é o consent gate."""

    targets: list[str] = Field(min_length=1)
    perspective: str = "unified"  # default do produto: público+privado num só scan
    objective: str = "standard"  # quick | standard | deep | ai
    # A IA SEMPRE comanda o scan (§3.4 — não há scan sem IA). Isto controla apenas
    # se as NARRATIVAS por IA (análise + remediação) são geradas ao final — um lever
    # de custo, nunca um "modo determinístico".
    use_ai: bool = True
    authorized: bool = False
    override_perspective: bool = False
    # Teto de IA do scan (§2.1): ao atingir, o scan encerra em paz. None = sem limite.
    max_ai_tokens: int | None = Field(default=None, ge=1)
    max_ai_cost_usd: float | None = Field(default=None, gt=0)


@app.post("/api/v1/scans", status_code=202)
def start_scan(req: ScanRequest, request: Request) -> dict:
    """Inicia um scan em background. Retorna o ``job_id`` para acompanhar o progresso.

    Recusa (403) sem afirmação de autorização — o consent gate é preservado. A
    concessão de consent é **auditada** no log estruturado (quem/quando/alvos)."""
    from ..logging_setup import get_logger

    client_host = request.client.host if request.client else "?"
    if req.authorized:
        get_logger("consent").info(
            "consent concedido para scan ativo",
            extra={
                "client": client_host,
                "targets": ",".join(req.targets)[:200],
                "perspective": req.perspective,
                "objective": req.objective,
            },
        )
    try:
        job = manager().start(
            targets=req.targets,
            perspective=req.perspective,
            objective=req.objective,
            authorized=req.authorized,
            use_ai=req.use_ai,
            override_perspective=req.override_perspective,
            max_ai_tokens=req.max_ai_tokens,
            max_ai_cost_usd=req.max_ai_cost_usd,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except AIProviderRequired as exc:
        # 428 Precondition Required: falta um provedor de IA (§3.4/ADR-0012).
        raise HTTPException(428, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return job.summary()


@app.get("/api/v1/jobs")
def list_jobs() -> list[dict]:
    return manager().list_jobs()


def _job_or_404(job_id: str):
    job = manager().get(job_id)
    if job is None:
        raise HTTPException(404, "job não encontrado")
    return job


@app.get("/api/v1/jobs/{job_id}")
def job_status(job_id: str) -> dict:
    return _job_or_404(job_id).summary()


@app.get("/api/v1/jobs/{job_id}/progress")
def job_progress(job_id: str, since: int = Query(default=0, ge=0)) -> dict:
    """Polling de progresso: eventos a partir de ``since`` + novo cursor (fallback ao WS)."""
    job = _job_or_404(job_id)
    evs, cursor = job.events_since(since)
    return {"status": job.status, "cursor": cursor, "events": evs}


@app.get("/api/v1/jobs/{job_id}/cascade-log")
def job_cascade_log(job_id: str) -> dict:
    """Log justificado de cada disparo de cascata (qual ferramenta e por quê)."""
    job = _job_or_404(job_id)
    return {"count": len(job.cascade_log), "cascade_log": job.cascade_log}


@app.post("/api/v1/jobs/{job_id}/cancel")
def job_cancel(job_id: str) -> dict:
    _job_or_404(job_id)
    ok = manager().cancel(job_id)
    return {"cancelled": ok}


@app.websocket("/ws/scans/{job_id}/progress")
async def scan_progress_ws(websocket: WebSocket, job_id: str) -> None:
    """Stream de progresso em tempo real: fases, descobertas, cascatas, execução.

    Faz replay do histórico ao conectar e depois entrega eventos novos conforme
    chegam ao buffer do job (ponte thread→async por polling curto do buffer)."""
    # Auth do WS (ADR-0014): o token vem por ?token= (o browser não seta header no
    # handshake). Recusa antes do accept quando inválido (1008 = policy violation).
    if not apitoken.token_matches(websocket.query_params.get("token")):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    job = manager().get(job_id)
    if job is None:
        await websocket.send_json({"type": "error", "message": "job não encontrado"})
        await websocket.close()
        return
    cursor = 0
    try:
        while True:
            evs, cursor = job.events_since(cursor)
            for event in evs:
                await websocket.send_json(event)
            if job.finished:
                evs, cursor = job.events_since(cursor)
                for event in evs:
                    await websocket.send_json(event)
                await websocket.send_json({"type": "stream_end", "status": job.status})
                break
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        return


# ── dashboard (SPA estática) ─────────────────────────────────────────────────
_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    index = _STATIC_DIR / "index.html"
    if not index.exists():
        return (
            "<h1>EIGAN</h1><p>API ativa. Veja <a href='/docs'>/docs</a> e "
            "<code>/api/v1/scans</code>.</p>"
        )
    html = index.read_text()
    # Modo local (loopback): injeta o token para o SPA usar sem fricção. Cross-origin
    # não consegue LER este HTML (same-origin policy), então o token não vaza para uma
    # página maliciosa. Exposto: NÃO injeta — o operador cola EIGAN_API_TOKEN (ADR-0014).
    if not app.state.exposed:
        token = apitoken.load_or_create_token()
        inject = f"<script>window.__EIGAN_TOKEN__={_json_str(token)};</script>"
        html = html.replace("</head>", inject + "</head>", 1)
    return html


def _json_str(value: str) -> str:
    """Serializa uma string para embutir com segurança em <script> (escapa </)."""
    import json

    return json.dumps(value).replace("</", "<\\/")


# assets estáticos (css/js/componentes). Montado por último para não capturar /api.
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
