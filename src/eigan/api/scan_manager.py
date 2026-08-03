"""Gerência de scans em background para a interface web (§5 do prompt de interface).

Um scan disparado pela UI roda em uma thread daemon enquanto a API continua
respondendo. Cada job mantém um **buffer de eventos** (fases, descobertas,
cascatas, execução de ferramenta) que a UI consome via WebSocket/polling em tempo
real. A camada de segurança é **preservada, não removida** (§2): o corpo do POST
precisa afirmar autorização — sem isso, o scan é recusado (equivalente ao consent
gate inline da CLI).

Este módulo é a fronteira entre o mundo síncrono/threaded do engine e o mundo
async da API: o :class:`~eigan.engine.cognitive.CognitiveEngine` emite eventos por um
:class:`~eigan.engine.events.EventSink` síncrono; o buffer é lido pelo
handler async. A ponte é um buffer protegido por lock (simples e robusto) — sem
malabarismo de event loop entre threads.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional, cast

if TYPE_CHECKING:
    from ..engine.cognitive import CompletionPort

from ..engine import events as ev
from ..engine.bus import EventBus
from ..engine.cognitive import Budget, CognitiveEngine, Goal, GoalKind
from ..engine.feeds import FeedCache
from ..engine.registry import PluginRegistry
from ..engine.risk import RiskScorer
from ..findings.store import FindingStore
from ..logging_setup import get_logger
from ..observability.metrics import MetricsCollector
from ..perspective import Perspective, validate_target
from ..security.onboarding import build_scope
from ..security.scope import ScopeViolation

log = get_logger("scan")

# perfis expostos pela UI → perfil interno do pipeline (engine/pipeline.py).
OBJECTIVE_PROFILE = {
    "quick": "quick",
    "standard": "standard",
    "deep": "deep",
    "ai": "standard",  # "deixe a IA decidir": IA orquestra sobre o pipeline padrão
}

# objetivo do EIGAN por perspectiva (foco v1.0: Web + Infra, Outside-In/Inside-Out).
# UNIFIED (default do produto) → avaliação completa: recon externo + rede num só scan.
_GOAL_BY_PERSPECTIVE = {
    Perspective.UNIFIED: GoalKind.FULL_ASSESSMENT,
    Perspective.EXTERNAL: GoalKind.ATTACK_SURFACE,
    Perspective.INTERNAL: GoalKind.NETWORK_ASSESSMENT,
}


class ScanCancelled(Exception):
    """Sinaliza cancelamento cooperativo — levantado no próximo evento emitido."""


@dataclass
class ScanJob:
    """Estado observável de um scan em andamento ou concluído."""

    id: str
    targets: list[str]
    perspective: str
    profile: str
    use_ai: bool = False
    status: str = "queued"  # queued | running | completed | failed | cancelled
    scan_id: Optional[int] = None  # id persistido (FindingStore) quando disponível
    error: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    cascade_log: list[dict[str, Any]] = field(default_factory=list)
    # Métricas ao vivo do scan (§22): assinam o event bus e agregam contadores.
    metrics: MetricsCollector = field(default_factory=MetricsCollector, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    # ── buffer de eventos (thread-safe) ─────────────────────────────────────
    def append(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.events.append(event)
            if event.get("type") == "cascade_log":
                self.cascade_log.append(event)
            if event.get("type") == "scan_status" and event.get("scan_id") is not None:
                self.scan_id = event["scan_id"]

    def events_since(self, index: int) -> tuple[list[dict[str, Any]], int]:
        """Eventos a partir de ``index`` e o novo cursor (para polling/WS)."""
        with self._lock:
            slice_ = self.events[index:]
            return list(slice_), len(self.events)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "targets": self.targets,
                "perspective": self.perspective,
                "profile": self.profile,
                "use_ai": self.use_ai,
                "status": self.status,
                "scan_id": self.scan_id,
                "error": self.error,
                "events": len(self.events),
                "cascade_tools": len({c["tool"] for c in self.cascade_log}),
                "metrics": self.metrics.snapshot(),
            }

    @property
    def finished(self) -> bool:
        return self.status in ("completed", "failed", "cancelled")

    def request_cancel(self) -> None:
        self._cancel.set()

    def _check_cancel(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled()


class _JobSink:
    """EventSink que grava no buffer do job e respeita cancelamento cooperativo."""

    def __init__(self, job: ScanJob) -> None:
        self._job = job

    def emit(self, event: dict[str, Any]) -> None:
        self._job.append(event)
        self._job._check_cancel()  # aborta no próximo ponto de emissão se pedido


class ScanManager:
    """Registro em memória dos jobs de scan. Um por processo de API."""

    def __init__(
        self, db_path: str = "eigan.db", registry: Optional[PluginRegistry] = None
    ) -> None:
        self._db_path = db_path
        # Registry injetável (DI) — o default descobre os plugins do repo/wheel.
        # Testes passam um registry controlado para rodar hermeticamente.
        self._registry = registry
        self._jobs: dict[str, ScanJob] = {}
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        # Copia sob o lock: os endpoints sync rodam no threadpool do FastAPI, e
        # iterar ``_jobs`` enquanto ``start()`` insere um job dispara
        # "dictionary changed size during iteration" (→ 500). ``summary()`` sai
        # do lock (só toma o lock por-job).
        with self._lock:
            jobs = list(self._jobs.values())
        return [j.summary() for j in jobs]

    def start(
        self,
        *,
        targets: list[str],
        perspective: str,
        objective: str,
        authorized: bool,
        use_ai: bool = False,
        override_perspective: bool = False,
        max_ai_tokens: int | None = None,
        max_ai_cost_usd: float | None = None,
    ) -> ScanJob:
        """Cria e inicia um job. ``authorized`` é o consent gate — obrigatório."""
        if not authorized:
            # Consent gate preservado (CLAUDE.md §2): nunca removido, só simplificado.
            raise PermissionError(
                "Autorização ausente: confirme que você tem permissão para escanear os alvos."
            )
        # Gate AI-native (§3.4/ADR-0012): EIGAN é um agente de IA — sem provedor,
        # não há scan. Levanta AIProviderRequired (mapeado p/ HTTP 428 no endpoint).
        from ..ai.provider import require_provider

        require_provider()
        if not targets:
            raise ValueError("Informe ao menos um alvo.")
        for t in targets:  # forma do alvo (§5): rejeita cedo (400) — anti argument-injection
            validate_target(t)
        try:
            persp = Perspective(perspective.strip().lower())
        except ValueError as exc:
            raise ValueError(f"Perspectiva inválida: {perspective!r}") from exc
        profile = OBJECTIVE_PROFILE.get(objective.strip().lower(), "standard")

        job = ScanJob(
            id="",  # atribuído sob o lock abaixo
            targets=list(targets),
            perspective=persp.value,
            profile=profile,
            use_ai=use_ai,
        )
        # Aloca o id E publica no dict sob o MESMO lock que os leitores
        # (get/list_jobs) usam — senão a inserção corre com a iteração.
        with self._lock:
            job.id = f"job-{next(self._counter)}"
            self._jobs[job.id] = job

        budget = (
            Budget(max_ai_tokens=max_ai_tokens, max_ai_cost_usd=max_ai_cost_usd)
            if (max_ai_tokens is not None or max_ai_cost_usd is not None)
            else None
        )
        thread = threading.Thread(
            target=self._run,
            args=(job, persp, profile, override_perspective, budget),
            name=f"scan-{job.id}",
            daemon=True,
        )
        thread.start()
        return job

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or job.finished:
            return False
        job.request_cancel()
        return True

    # ── execução ────────────────────────────────────────────────────────────
    def _run(
        self,
        job: ScanJob,
        perspective: Perspective,
        profile: str,
        override: bool,
        budget: Budget | None = None,
    ) -> None:
        job.status = "running"
        # Event bus (§9/§13): o engine publica uma vez; o bus distribui. As métricas
        # assinam PRIMEIRO (observam mesmo se o scan abortar); o sink do job (que
        # dispara o cancelamento cooperativo ao levantar) vem por último.
        sink = _JobSink(job)
        bus = EventBus()
        bus.subscribe(job.metrics)
        bus.subscribe(sink)
        log.info(
            "scan iniciado",
            extra={
                "event": "scan_start",
                "job": job.id,
                "targets": ",".join(job.targets),
                "perspective": perspective.value,
                "profile": profile,
                "use_ai": job.use_ai,
            },
        )
        try:
            scope = build_scope(None, job.targets, perspective)
            feeds = FeedCache.load()
            risk = RiskScorer(feeds, online=False)  # enriquecimento online é opt-in
            store = FindingStore(self._db_path)
            # §3.4 (AI-native, tudo-ou-nada): a IA comanda TODO scan real. O provedor
            # já foi exigido em start(), então o AgenticPlanner SEMPRE o usa — não há
            # caminho determinístico que produza um scan sem a IA. Se a chamada de IA
            # falhar, o próprio planner cai no substrato (falha de agente reportada,
            # não "rodar sem IA"). `use_ai` NÃO desliga o planejador — controla apenas
            # se as NARRATIVAS por IA (análise/remediação) também são geradas.
            from ..ai.provider import require_provider

            completion = cast("CompletionPort", require_provider())
            # Policy Engine (ADR-0011): sob o consent do engajamento, ações HITL são
            # auto-aprovadas (e auditadas na timeline); exploit exige allow_exploit.
            from ..policy.engine import AutoApprove

            engine = CognitiveEngine(
                self._registry,
                risk=risk,
                store=store,
                completion=completion,
                approver=AutoApprove(),
            )
            goal = Goal.build(
                _GOAL_BY_PERSPECTIVE.get(perspective, GoalKind.ATTACK_SURFACE),
                job.targets,
                perspective=perspective,
                profile=profile,
                budget=budget,
            )
            for t in job.targets:  # falha rápida se um alvo é totalmente não autorizado
                scope.enforce(t, perspective=perspective, override=override)
            # Intensidade → opções de ferramenta (rate/timing/stealth/portas): a
            # mesma capacidade roda com as melhores opções para o objetivo.
            from ..engine.tuning import tool_options

            opts = tool_options(profile, perspective)
            # allow_exploit=True: o consent do engajamento autoriza validação de
            # exploração (sqlmap/dalfox não-destrutivos); a política ainda a gate via HITL.
            report = engine.run(
                goal,
                scope=scope,
                override_perspective=override,
                allow_exploit=True,
                sink=bus,
                **opts,
            )
            # Analysis Engine (auto): a IA analisa o scan inteiro e conclui — o
            # usuário não precisa clicar. Roda quando há achados (nada a analisar num
            # scan vazio) e `use_ai` pede as narrativas (lever de custo — não gastar
            # tokens à toa). O PLANNER já usou a IA acima (§3.4), independente disto.
            if report.scan_id is not None and report.findings and job.use_ai:
                sink.emit(ev.log("[análise] IA correlacionando os achados e concluindo…"))
                from ..analysis.engine import analyze_and_store, remediate_and_store

                text = analyze_and_store(store, report.scan_id, provider=completion)
                if text:
                    sink.emit({"type": "analysis", "scan_id": report.scan_id, "text": text})
                # Plano de remediação da IA (o que arrumar + como): auto, ao fim do
                # scan — o operador não precisa clicar. Degrada sem quebrar.
                sink.emit(ev.log("[remediação] IA montando o plano de correção priorizado…"))
                rem = remediate_and_store(store, report.scan_id, provider=completion)
                if rem:
                    sink.emit({"type": "remediation", "scan_id": report.scan_id})
            store.close()
            job.status = "completed"
            log.info(
                "scan concluído",
                extra={
                    "event": "scan_done",
                    "job": job.id,
                    "scan_id": report.scan_id,
                    "findings": len(report.findings),
                },
            )
        except ScanCancelled:
            job.status = "cancelled"
            self._mark_scan_status(job.scan_id, "cancelled")
            log.info("scan cancelado", extra={"event": "scan_cancelled", "job": job.id})
            job.append(ev.scan_status(job.scan_id, "cancelled", "cancelado pelo usuário"))
        except ScopeViolation as exc:
            job.status = "failed"
            job.error = str(exc)
            self._mark_scan_status(job.scan_id, "failed")
            log.warning(
                "scan bloqueado por escopo",
                extra={"event": "scan_blocked", "job": job.id, "reason": str(exc)},
            )
            job.append(ev.scan_status(job.scan_id, "failed", f"bloqueado: {exc}"))
        except Exception as exc:  # noqa: BLE001 — erro de scan não derruba a API
            job.status = "failed"
            self._mark_scan_status(job.scan_id, "failed")
            log.error(
                "scan falhou", extra={"event": "scan_failed", "job": job.id, "error": str(exc)}
            )
            job.error = str(exc)
            job.append(ev.scan_status(job.scan_id, "failed", str(exc)))

    def _mark_scan_status(self, scan_id: Optional[int], status: str) -> None:
        """Marca o status do scan persistido (ADR-0017) — os findings parciais já
        gravados incrementalmente permanecem legíveis. Best-effort: nunca levanta."""
        if scan_id is None:
            return
        try:
            store = FindingStore(self._db_path)
            store.finish_scan(scan_id, status=status)
            store.close()
        except Exception as exc:  # noqa: BLE001
            log.warning("não foi possível marcar status %s do scan %s: %s", status, scan_id, exc)
