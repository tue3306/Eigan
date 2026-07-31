"""Execução de scan compartilhada entre o comando ``scan`` e o wizard.

Centraliza a sequência: aceite de termo (1ª execução) → escopo (arquivo ou
efêmero) → consent inline → risco (EPSS/KEV offline por padrão) → orquestração.
Assim CLI e wizard não duplicam a política de segurança.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from ..engine.cognitive import (
    Budget,
    CognitiveEngine,
    CognitiveReport,
    DecisionEntry,
    Goal,
    GoalKind,
)

if TYPE_CHECKING:
    from ..engine.cognitive import CompletionPort
from ..engine.feeds import FeedCache
from ..engine.orchestrator import ScanReport
from ..engine.registry import PluginRegistry
from ..engine.risk import RiskScorer
from ..findings.store import FindingStore
from ..perspective import Perspective
from ..security.consent import ConsentDenied, ConsentGate
from ..security.onboarding import accept_terms, build_scope


class SessionAborted(Exception):
    """Fluxo interrompido por recusa de termo/consentimento (não é erro técnico)."""


@dataclass
class ScanOutcome:
    # A IA comanda o scan (CognitiveReport); o tipo aceita ScanReport por compat
    # com quem ainda usa o Orchestrator determinístico direto (testes/pipeline).
    report: "ScanReport | CognitiveReport"
    feeds_meta: dict


class _CliApprover:
    """Aprovação humana (HITL) na CLI (ADR-0011): pergunta ao operador quando a
    política marca uma ação como NEEDS_APPROVAL. ``--yes`` (assume_yes) auto-aprova
    (o consent não-interativo já autorizou o engajamento)."""

    _YES = {"s", "sim", "y", "yes"}

    def __init__(self, assume_yes: bool, input_fn, echo) -> None:
        self._yes = assume_yes
        self._input = input_fn
        self._echo = echo

    def approve(self, action) -> bool:
        if self._yes:
            return True
        prompt = (
            f"[HITL] Aprovar {action.tool} ({action.impact_class.value}) → {action.target}? [s/N]: "
        )
        try:
            return self._input(prompt).strip().lower() in self._YES
        except (EOFError, KeyboardInterrupt):
            return False


class _ProgressSink:
    """Adapta os eventos do :class:`CognitiveEngine` para o callback textual do
    CLI/wizard — o operador vê a IA **raciocinar** (plano/replan) e as ferramentas
    executarem em tempo real. Antes o scan da CLI nem passava pela IA."""

    def __init__(self, progress) -> None:
        self._p = progress

    def emit(self, event: dict) -> None:
        if self._p is None:
            return
        kind = event.get("type")
        if kind == "log":
            msg = event.get("message", "")
            if msg:
                self._p(msg)
        elif kind == "tool_execution":
            status = event.get("status", "")
            if status in ("in_progress", "completed", "failed", "skipped"):
                detail = event.get("detail", "")
                line = f"[{status}] {event.get('tool', '?')} → {event.get('target', '?')}"
                self._p(line + (f"  ({detail})" if detail else ""))
        elif kind == "discovery":
            fnd = event.get("finding", {})
            self._p(
                f"descoberta: [{fnd.get('severity', '?')}] {fnd.get('title', '?')} "
                f"({fnd.get('affected_asset', '?')})"
            )


def feeds_meta(feeds: FeedCache) -> dict:
    """Metadados de procedência dos feeds para o relatório (datas ou vazio)."""
    return {"kev": feeds.kev_date() if feeds.kev_available else "", "epss": feeds.epss_date()}


@dataclass
class PlanOutcome:
    """Resultado do comando ``plan`` (núcleo cognitivo, ADR-0007)."""

    goal: Goal
    planner_name: str
    ai_used: bool
    decisions: list[DecisionEntry]
    report: CognitiveReport | None = None  # None em dry-run (nada executado)
    suggestions: list = field(default_factory=list)


def _budget(max_ai_tokens: int | None, max_ai_cost_usd: float | None) -> Budget | None:
    """Budget com o teto de IA declarado (§2.1); None → usa o default do Goal."""
    if max_ai_tokens is None and max_ai_cost_usd is None:
        return None
    return Budget(max_ai_tokens=max_ai_tokens, max_ai_cost_usd=max_ai_cost_usd)


def plan_scan(
    *,
    goal_kind: GoalKind,
    targets: list[str],
    perspective: Perspective | None,
    profile: str,
    scope_path: str | None,
    db: str,
    assume_yes: bool,
    override_perspective: bool,
    online_enrich: bool,
    dry_run: bool,
    use_ai: bool,
    max_ai_tokens: int | None = None,
    max_ai_cost_usd: float | None = None,
    input_fn=input,
    echo=print,
) -> PlanOutcome:
    """Roda o núcleo cognitivo goal-driven (Planner → seleção → execução).

    ``dry_run`` mostra o plano e a seleção justificada **sem executar** — por isso
    não passa pelo consent gate. A execução real exige termo + escopo + consent,
    exatamente como :func:`execute_scan`.
    """
    goal = Goal.build(
        goal_kind,
        targets,
        perspective=perspective,
        profile=profile,
        budget=_budget(max_ai_tokens, max_ai_cost_usd),
    )
    registry = PluginRegistry.discover()

    if dry_run:
        # Preview seguro (nada executa, nada toca a rede): não exige provedor.
        engine = CognitiveEngine(registry, completion=_completion(use_ai))
        planner, decisions = engine.plan_only(goal)
        return PlanOutcome(
            goal=goal,
            planner_name=planner.name,
            ai_used=bool(getattr(planner, "ai_generated", False)),
            decisions=decisions,
        )

    # Execução real: a IA é obrigatória (§3.4/ADR-0012). Sem provedor → recusa
    # acionável antes de qualquer prompt. A IA comanda o scan (AgenticPlanner).
    completion = _require_completion()
    if not accept_terms(assume_yes=assume_yes, input_fn=input_fn, echo=echo):
        raise SessionAborted("Termo de uso não aceito.")
    scope = build_scope(scope_path, targets, goal.perspective)
    try:
        ConsentGate(scope.engagement, targets).require(assume_yes=assume_yes, input_fn=input_fn)
    except ConsentDenied as exc:
        raise SessionAborted(str(exc)) from exc

    feeds = FeedCache.load()
    risk = RiskScorer(feeds, online=online_enrich)
    store = FindingStore(db)
    approver = _CliApprover(assume_yes, input_fn, echo)
    engine = CognitiveEngine(
        registry, risk=risk, store=store, completion=completion, approver=approver
    )
    report = engine.run(
        goal, scope=scope, override_perspective=override_perspective, allow_exploit=True
    )
    return PlanOutcome(
        goal=goal,
        planner_name=report.planner_name,
        ai_used=report.ai_used,
        decisions=report.decisions,
        report=report,
        suggestions=report.suggestions,
    )


def _completion(use_ai: bool) -> "CompletionPort | None":
    """Provedor de IA para o preview (dry-run). None se não pedido/indisponível —
    o dry-run é só uma prévia do plano, não uma execução."""
    if not use_ai:
        return None
    from ..ai.provider import default_provider

    return cast("CompletionPort | None", default_provider())


def _require_completion() -> "CompletionPort":
    """Gate AI-native (§3.4/ADR-0012): exige um provedor para executar de verdade.

    Levanta ``AIProviderRequired`` (acionável) se nenhum provedor está configurado.
    Os provedores concretos (`_HTTPProvider`) implementam ``complete`` — a porta
    que a IA usa para comandar o scan."""
    from ..ai.provider import require_provider

    return cast("CompletionPort", require_provider())


def execute_scan(
    *,
    targets: list[str],
    perspective: Perspective | None,
    profile: str,
    scope_path: str | None,
    db: str,
    assume_yes: bool,
    override_perspective: bool,
    online_enrich: bool,
    max_ai_tokens: int | None = None,
    max_ai_cost_usd: float | None = None,
    progress=None,
    input_fn=input,
    echo=print,
    goal_kind: GoalKind = GoalKind.FULL_ASSESSMENT,
) -> ScanOutcome:
    """Executa um scan **comandado pela IA** (núcleo cognitivo, ADR-0007/0009).

    A IA planeja as capacidades (objetivo → estratégia), reage a cada descoberta
    e **replaneja em ondas**; o engine determinístico traduz cada capacidade na
    ferramenta concreta e a executa com o runner seguro, dentro do escopo. É o
    mesmo motor da API/dashboard — antes o ``eigan scan``/wizard rodavam um
    pipeline fixo sem IA, contrariando §3.4/§7/§18.

    Sem provedor de IA o scan é recusado com erro acionável (§3.4), antes de
    qualquer prompt de termo/consent.
    """
    completion = _require_completion()
    if not accept_terms(assume_yes=assume_yes, input_fn=input_fn, echo=echo):
        raise SessionAborted("Termo de uso não aceito.")

    # O objetivo resolve a perspectiva default (FULL_ASSESSMENT → UNIFIED, modo
    # produto); --perspective explícito sobrepõe. O guardrail de escopo é
    # revalidado por alvo dentro do engine (defesa em profundidade).
    goal = Goal.build(
        goal_kind,
        targets,
        perspective=perspective,
        profile=profile,
        budget=_budget(max_ai_tokens, max_ai_cost_usd),
    )
    scope = build_scope(scope_path, targets, goal.perspective)
    try:
        ConsentGate(scope.engagement, targets).require(assume_yes=assume_yes, input_fn=input_fn)
    except ConsentDenied as exc:
        raise SessionAborted(str(exc)) from exc

    feeds = FeedCache.load()
    risk = RiskScorer(feeds, online=online_enrich)
    store = FindingStore(db)
    registry = PluginRegistry.discover()
    approver = _CliApprover(assume_yes, input_fn, echo)
    engine = CognitiveEngine(
        registry, risk=risk, store=store, completion=completion, approver=approver
    )
    report = engine.run(
        goal,
        scope=scope,
        override_perspective=override_perspective,
        allow_exploit=True,
        sink=_ProgressSink(progress),
    )
    return ScanOutcome(report=report, feeds_meta=feeds_meta(feeds))
