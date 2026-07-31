"""CognitiveEngine — o loop goal-driven (ADR-0007).

Amarra os contratos: ``Goal → Planner → [Agent → ToolSelector → Execution] →
Feedback → replan → StopCondition``. Reusa o Capability Registry
(:class:`PluginRegistry`) e a execução segura existente — **não** reimplementa
subprocess nem escopo. Cada decisão vira uma :class:`DecisionEntry` (capacidade,
ferramenta escolhida, motivos, alternativas) — o rastro auditável exigido pelo
§3.4 do CLAUDE.md.

Modelo EIGAN (ADR-0009): a IA **comanda** o plano (AgenticPlanner) — planeja e
replaneja por onda. Dois invariantes de código a cercam (não a limitam):
* `SafeExecution` valida escopo por alvo antes de rodar o runner seguro — a IA
  nunca opera fora do escopo autorizado.
* Grounding: a IA só age sobre capacidades reais do registry; o `ToolSelector`
  (determinístico) escolhe a ferramenta concreta e a cascata é o piso de segurança.
* Agente scaffold / capacidade sem ferramenta ⇒ *sugerido, não executado*.
Cada passo é emitido como evento `log` (timeline de raciocínio, sem caixa-preta).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

from ...findings.dedup import deduplicate
from ...findings.schema import Finding
from ...findings.store import FindingStore
from ...observability.cost import CostModel
from ...observability.usage import TokenUsage, UsageMeter, use_meter
from ...perspective import Perspective
from ...policy.engine import (
    PolicyEngine,
    ProposedAction,
    Verdict,
    ceiling_for_profile,
)
from ...security.scope import Scope, ScopeViolation
from .. import events as ev
from ..cascade import CascadeGraph
from ..events import EventSink, NullSink
from ..plugin import PluginSpec
from ..registry import PluginRegistry
from ..risk import RiskScorer
from .agent import AgentRegistry
from .feedback import Feedback, ScanState, StopCondition, StopReason, Suggestion
from .goal import Budget, Goal
from .planner import AgenticPlanner, CompletionPort, DeterministicPlanner, Planner
from .selection import Prefer, SelectionContext, ToolSelector

log = logging.getLogger("eigan.cognitive")

# perfil de scan → o que o Tool Selection Engine prioriza.
_PREFER_BY_PROFILE: dict[str, Prefer] = {
    "quick": Prefer.SPEED,
    "deep": Prefer.ACCURACY,
}


class ExecutionPort(Protocol):
    """Porta de execução — o engine não conhece subprocess, só esta interface."""

    def execute(
        self, spec: PluginSpec, target: str, perspective: Perspective, **opts
    ) -> list[Finding]: ...


class ApprovalPort(Protocol):
    """Aprovação humana (HITL) de uma ação que a política marcou NEEDS_APPROVAL.

    Retorna ``True`` para autorizar a execução, ``False`` para pular. O CLI pergunta
    ao operador (a menos que ``--yes``); a API auto-aprova sob o consent do
    engajamento (e audita). Ausente (``None``) ⇒ ação HITL é **bloqueada** (seguro)."""

    def approve(self, action: ProposedAction) -> bool: ...


@dataclass
class SafeExecution:
    """Execução segura: valida escopo por alvo, então roda o runner do plugin.

    Espelha a política do `Orchestrator` (subprocess com lista de args, nunca
    ``shell=True``). ``ScopeViolation`` sobe para o loop, que a registra como
    *fora de escopo* e segue — nunca derruba o scan."""

    scope: Scope
    override: bool = False

    def execute(
        self, spec: PluginSpec, target: str, perspective: Perspective, **opts
    ) -> list[Finding]:
        self.scope.enforce(target, perspective=perspective, override=self.override)
        # Passa a perspectiva ao runner (opt-in): sondas HTTP nativas (exposure) a
        # usam para decidir allow_private na blindagem de SSRF (ADR-0015). Runners
        # que não a consomem simplesmente a ignoram (BaseToolPlugin.scan tem **options).
        findings = spec.scan(target, perspective=perspective.value, **opts)
        for f in findings:
            f.perspective = perspective
        return findings


@dataclass
class DecisionEntry:
    """Uma linha do rastro de decisões — tudo logado e justificado."""

    step: int
    capability: str
    agent: str
    action: str  # selected | executed | skipped | failed | suggested | scaffold | stop
    tool: str = ""
    reasons: tuple[str, ...] = ()
    findings: int = 0
    origin: str = ""
    detail: str = ""

    def render(self) -> str:
        head = f"#{self.step} [{self.action}] {self.capability}"
        if self.agent:
            head += f" · agente={self.agent}"
        if self.tool:
            head += f" · {self.tool}"
        if self.findings:
            head += f" · {self.findings} finding(s)"
        if self.reasons:
            head += "  ← " + "; ".join(self.reasons)
        if self.detail:
            head += f"  ({self.detail})"
        return head


@dataclass
class CognitiveReport:
    goal: Goal
    scan_id: Optional[int]
    findings: list[Finding]
    decisions: list[DecisionEntry]
    stop_reason: StopReason
    planner_name: str
    ai_used: bool
    suggestions: list[Suggestion] = field(default_factory=list)
    # Alvos descobertos pela recon e realimentados como novos alvos (ADR-0018).
    discovered_targets: list[str] = field(default_factory=list)
    # Uso de tokens da IA no scan (observabilidade §22, ADR-0025): cobre o loop
    # cognitivo (planejamento + replan adaptativo). Zero quando não há IA.
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    ai_calls: int = 0
    token_usage_by_model: dict[str, TokenUsage] = field(default_factory=dict)

    # Compat com ScanReport: o CLI/wizard/relatório consomem estes campos sem
    # precisar saber qual engine (determinístico × cognitivo) produziu o report.
    @property
    def perspective(self) -> Perspective:
        """Perspectiva efetiva do scan (derivada do objetivo)."""
        return self.goal.perspective

    @property
    def skipped_tools(self) -> list[str]:
        """Ferramentas sugeridas mas não executadas (indisponíveis/roadmap)."""
        return [s.tool for s in self.suggestions]


class _MeteredCompletion:
    """Envolve a porta de IA para medir tokens por scan (observabilidade, ADR-0025).

    Cada ``complete()`` roda sob o medidor do scan (``use_meter``); o provedor HTTP
    registra o uso real ali dentro (``_post`` → ``record_completion``). Assim o loop
    cognitivo (``run``) permanece intocado — a medição é transparente e escopada por
    execução (contextvar), correta mesmo com scans concorrentes em threads."""

    def __init__(self, inner: CompletionPort, meter_holder: "CognitiveEngine") -> None:
        self._inner = inner
        self._holder = meter_holder

    def available(self) -> bool:
        return self._inner.available()

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        with use_meter(self._holder._scan_meter):
            return self._inner.complete(system, user, json_mode=json_mode)


class CognitiveEngine:
    """Orquestrador goal-driven: planeja capacidades, seleciona ferramentas,
    executa com escopo e replaneja pela descoberta — tudo auditável."""

    def __init__(
        self,
        registry: Optional[PluginRegistry] = None,
        *,
        planner: Optional[Planner] = None,
        agents: Optional[AgentRegistry] = None,
        selector: Optional[ToolSelector] = None,
        risk: Optional[RiskScorer] = None,
        store: Optional[FindingStore] = None,
        completion: Optional[CompletionPort] = None,
        approver: Optional[ApprovalPort] = None,
    ) -> None:
        # Aprovador HITL (ADR-0011 Fase 3): chamado quando a política pede aprovação
        # humana. None ⇒ ações HITL são bloqueadas (seguro por padrão).
        self._approver = approver
        self._registry = registry if registry is not None else PluginRegistry.discover()
        self._graph = CascadeGraph.from_registry(self._registry)
        self._agents = agents if agents is not None else AgentRegistry.default()
        self._selector = selector if selector is not None else ToolSelector(self._registry)
        self._risk = risk
        self._store = store
        # Planner: AgenticPlanner (IA comanda o plano fim a fim) quando há um
        # provedor; senão o DeterministicPlanner — o substrato determinístico que
        # a IA comanda (§3.4), não um "modo sem IA": o gate de produto exige um
        # provedor antes de chegar aqui.
        # Medidor de tokens do scan corrente (observabilidade §22, ADR-0025): é
        # reatribuído a cada run() para isolar scans; a completion metrificada o lê
        # ao vivo. Fica vazio quando não há IA (sem provedor → sem tokens).
        self._scan_meter = UsageMeter()
        # Modelo de custo (§2.1): preços verificados pelo operador (ou vazio → custo
        # UNVERIFIED). Alimenta o teto de custo de IA; o teto de token é o piso confiável.
        self._cost_model = CostModel.from_config()
        base = DeterministicPlanner(self._registry, self._graph)
        if planner is not None:
            self._planner: Planner = planner
        elif completion is not None and completion.available():
            self._planner = AgenticPlanner(base, _MeteredCompletion(completion, self))
        else:
            self._planner = base

    @property
    def planner(self) -> Planner:
        return self._planner

    def plan_only(self, goal: Goal) -> tuple[Planner, list[DecisionEntry]]:
        """Constrói o plano inicial e a seleção **sem executar** (dry-run).

        Não passa pelo consent gate: nada ativo roda. Serve ao comando
        ``plan --dry-run`` para mostrar o Planner escolhendo/justificando."""
        plan = self._planner.initial_plan(goal)
        ctx = self._base_context(goal)
        decisions: list[DecisionEntry] = []
        for i, step in enumerate(plan.steps, start=1):
            agent = self._agents.for_capability(step.capability)
            if agent is None or not agent.built:
                decisions.append(
                    DecisionEntry(
                        step=i,
                        capability=step.capability.value,
                        agent=agent.name if agent else "—",
                        action="scaffold",
                        origin=step.origin,
                        detail="agente não construído (sugerido, não executado)",
                    )
                )
                continue
            choice = self._selector.select(step.capability, ctx)
            if choice is None:
                decisions.append(
                    DecisionEntry(
                        step=i,
                        capability=step.capability.value,
                        agent=agent.name,
                        action="suggested",
                        origin=step.origin,
                        reasons=("nenhuma ferramenta instalada provê esta capacidade",),
                    )
                )
                continue
            decisions.append(
                DecisionEntry(
                    step=i,
                    capability=step.capability.value,
                    agent=agent.name,
                    action="selected",
                    tool=choice.tool,
                    reasons=choice.reasons,
                    origin=step.origin,
                )
            )
        return self._planner, decisions

    def run(
        self,
        goal: Goal,
        *,
        scope: Scope,
        execution: Optional[ExecutionPort] = None,
        override_perspective: bool = False,
        allow_exploit: bool = False,
        sink: Optional[EventSink] = None,
        **tool_opts,
    ) -> CognitiveReport:
        """Executa o loop cognitivo. O chamador deve ter passado pelo consent gate
        (autorização) antes; aqui o escopo é revalidado por alvo (defesa em
        profundidade) e **cada ação ativa passa pelo Policy Engine** (ADR-0011)."""
        emitter: EventSink = sink if sink is not None else NullSink()
        # Medidor de tokens fresco por scan (observabilidade §22, ADR-0025): a
        # completion metrificada registra aqui todo o uso do loop cognitivo.
        self._scan_meter = UsageMeter()
        # Policy Engine (ADR-0011 Fase 3): arbitra CADA ação ativa antes de tocar a
        # rede — executar / aprovação humana (HITL) / recusar por ImpactClass. O teto
        # autônomo vem do perfil; exploit_validation exige allow_exploit + HITL.
        policy = PolicyEngine(
            scope=scope,
            perspective=goal.perspective,
            allow_exploit=allow_exploit,
            auto_approve_ceiling=ceiling_for_profile(goal.profile),
            override_perspective=override_perspective,
        )
        exec_port: ExecutionPort = (
            execution
            if execution is not None
            else SafeExecution(scope, override=override_perspective)
        )
        persp = goal.perspective

        scan_id: Optional[int] = None
        if self._store is not None:
            scan_id = self._store.create_scan(
                scope.engagement or goal.kind.value,
                f"{persp.value}/{goal.profile}",
                list(goal.targets),
            )
        emitter.emit(ev.scan_status(scan_id, "running", goal.kind.label))

        plan = self._planner.initial_plan(goal)
        state = ScanState()
        stop = StopCondition(goal.budget)
        decisions: list[DecisionEntry] = []

        # Working-set de alvos (ADR-0018): começa com os originais e CRESCE com o que
        # a recon descobrir (subdomínios/IPs/hosts), cada um após o gate de escopo e
        # sob o teto duro. As capacidades seguintes escaneiam este conjunto.
        from ...perspective import extract_host

        working_targets: list[str] = []
        working_hosts: set[str] = set()
        for t in goal.targets:
            key = extract_host(t).lower() or t.lower()
            if key not in working_hosts:
                working_hosts.add(key)
                working_targets.append(t)

        # Timeline: registra o raciocínio inicial da IA (ou do determinístico).
        driver = "IA" if getattr(self._planner, "ai_generated", False) else "determinístico"
        plan_entry = DecisionEntry(
            step=0,
            capability="",
            agent="",
            action="planned",
            origin=self._planner.name,
            reasons=tuple(f"{s.capability.value}: {s.reason}" for s in plan.steps),
            detail=f"plano por {driver}: {', '.join(c.value for c in plan.capabilities())}",
        )
        decisions.append(plan_entry)
        emitter.emit(ev.log(plan_entry.render()))
        stop_hint = getattr(self._planner, "stop_hint", "")
        if stop_hint:
            emitter.emit(ev.log(f"#0 [stop-hint] IA sugere encerrar quando: {stop_hint}"))

        base_ctx = self._base_context(goal)
        stop_reason = StopReason.PLAN_EXHAUSTED
        step_no = 0

        while True:
            budget_hit = stop.check(state)
            if budget_hit is not None:
                stop_reason = budget_hit
                break

            # Teto de IA (§2.1): antes de qualquer nova onda (execução + replan, que é
            # a próxima chamada de IA), verifica o consumo acumulado e encerra em paz.
            ai_budget_hit = self._ai_budget_stop(goal.budget)
            if ai_budget_hit is not None:
                stop_reason = ai_budget_hit
                emitter.emit(ev.log(f"[orçamento-IA] encerrando o scan: {ai_budget_hit.value}"))
                break

            step = plan.pop_next()
            if step is None:
                stop_reason = (
                    StopReason.NO_NEW_EVIDENCE if state.findings else StopReason.PLAN_EXHAUSTED
                )
                break

            if step.capability in state.executed_capabilities:
                continue  # já coberta (evita re-execução após replan)

            step_no += 1
            # Timeline de raciocínio: por que esta capacidade está no plano
            # (estratégia | cascata determinística | onda adaptativa da IA).
            emitter.emit(
                ev.log(f"#{step_no} [plano:{step.origin}] {step.capability.value} ← {step.reason}")
            )
            agent = self._agents.for_capability(step.capability)
            if agent is None or not agent.built:
                d = DecisionEntry(
                    step=step_no,
                    capability=step.capability.value,
                    agent=agent.name if agent else "—",
                    action="scaffold",
                    origin=step.origin,
                    detail="agente não construído (sugerido, não executado)",
                )
                decisions.append(d)
                emitter.emit(ev.log(d.render()))
                state.executed_capabilities.add(step.capability)
                continue

            ctx = base_ctx.with_tags(state.context_tags)
            choice = self._selector.select(step.capability, ctx)
            if choice is None:
                d = DecisionEntry(
                    step=step_no,
                    capability=step.capability.value,
                    agent=agent.name,
                    action="suggested",
                    origin=step.origin,
                    reasons=("nenhuma ferramenta instalada provê esta capacidade",),
                )
                decisions.append(d)
                emitter.emit(ev.log(d.render()))
                state.executed_capabilities.add(step.capability)
                continue

            sel = DecisionEntry(
                step=step_no,
                capability=step.capability.value,
                agent=agent.name,
                action="selected",
                tool=choice.tool,
                reasons=choice.reasons,
                origin=step.origin,
            )
            decisions.append(sel)
            emitter.emit(ev.log(sel.render()))

            step_findings, duration = self._execute_step(
                exec_port,
                choice.spec,
                goal,
                persp,
                step_no,
                agent.name,
                decisions,
                emitter,
                tool_opts,
                list(working_targets),  # snapshot: escaneia o working-set atual
                policy,
                step.capability.value,
            )
            state.absorb(Feedback(step.capability, choice.tool, step_findings, duration))
            # Expansão de alvos dirigida por descoberta (ADR-0018): os hosts/IPs/
            # subdomínios recém-descobertos entram no working-set (gate de escopo +
            # teto), para as capacidades seguintes escaneá-los.
            self._expand_targets(
                step_findings,
                working=working_targets,
                working_hosts=working_hosts,
                scope=scope,
                persp=persp,
                override=override_perspective,
                budget_max=goal.budget.max_targets,
                emitter=emitter,
                state=state,
            )
            # Persistência incremental (ADR-0017): grava as descobertas desta onda
            # AGORA — se o scan for morto/timeout depois, nada do que já achamos se
            # perde. O _finalize só consolida/dedupa/pontua sobre o que já está lá.
            self._persist_incremental(scan_id, step_findings, state)
            done = DecisionEntry(
                step=step_no,
                capability=step.capability.value,
                agent=agent.name,
                action="executed",
                tool=choice.tool,
                findings=len(step_findings),
                origin=step.origin,
            )
            decisions.append(done)
            emitter.emit(ev.log(done.render()))

            # replan dirigido por descoberta: piso determinístico (cascata) +
            # onda adaptativa da IA. Emite os passos acrescentados (timeline).
            before = set(plan.capabilities())
            self._planner.replan(goal, state, plan)
            for s in plan.steps:
                if s.capability not in before and s.origin in ("cascade", "ai"):
                    emitter.emit(
                        ev.log(f"#{step_no} [replan:{s.origin}] +{s.capability.value} ← {s.reason}")
                    )
            state.mark_replanned()

        return self._finalize(goal, scan_id, state, decisions, stop_reason, emitter)

    # ── auxiliares ────────────────────────────────────────────────────────────
    def _execute_step(
        self,
        exec_port: ExecutionPort,
        spec: PluginSpec,
        goal: Goal,
        persp: Perspective,
        step_no: int,
        agent_name: str,
        decisions: list[DecisionEntry],
        emitter: EventSink,
        tool_opts: dict,
        targets: list[str],
        policy: PolicyEngine,
        capability: str,
    ) -> tuple[list[Finding], float]:
        findings: list[Finding] = []
        started = time.monotonic()
        # Cobertura parcial (§3.1): se a ferramenta declara chaves opcionais e elas
        # faltam, avisa na timeline o que NÃO será coletado — sem fingir cobertura.
        coverage = spec.coverage_note()
        if coverage:
            emitter.emit(ev.log(f"[cobertura] {coverage}"))
        # Escaneia o working-set (alvos originais + descobertos), não só os originais
        # (ADR-0018: expansão dirigida por descoberta).
        for target in targets:
            # Policy Engine (ADR-0011): arbitra ESTA ação (ferramenta×alvo) antes de
            # tocar a rede — executar / HITL / recusar por ImpactClass.
            if not self._vet_action(spec, target, capability, policy, emitter, decisions, step_no):
                continue  # recusada ou HITL não aprovada — pulada (auditada), nunca roda
            emitter.emit(ev.tool_execution(spec.name, target, "in_progress"))
            try:
                produced = exec_port.execute(spec, target, persp, **tool_opts)
                findings.extend(produced)
                # streaming em tempo real: cada descoberta vai ao feed do dashboard,
                # já anotada com as ferramentas que ela dispararia (intenção da cascata).
                for f in produced:
                    triggers = [t.tool for t in self._graph.triggered_by(f)]
                    emitter.emit(ev.discovery(f, triggers))
            except ScopeViolation as exc:
                decisions.append(
                    DecisionEntry(
                        step=step_no,
                        capability="",
                        agent=agent_name,
                        action="skipped",
                        tool=spec.name,
                        detail=f"fora de escopo: {exc}",
                    )
                )
                emitter.emit(ev.tool_execution(spec.name, target, "skipped", detail=str(exc)))
            except Exception as exc:  # noqa: BLE001 — um plugin (ToolNotAvailable/erro) não derruba o loop
                decisions.append(
                    DecisionEntry(
                        step=step_no,
                        capability="",
                        agent=agent_name,
                        action="failed",
                        tool=spec.name,
                        detail=str(exc),
                    )
                )
                emitter.emit(ev.tool_execution(spec.name, target, "failed", detail=str(exc)))
            else:
                emitter.emit(ev.tool_execution(spec.name, target, "completed", 100))
        return findings, time.monotonic() - started

    def _vet_action(
        self,
        spec: PluginSpec,
        target: str,
        capability: str,
        policy: PolicyEngine,
        emitter: EventSink,
        decisions: list[DecisionEntry],
        step_no: int,
    ) -> bool:
        """Submete a ação ao Policy Engine (ADR-0011). Retorna True se pode rodar.

        EXECUTE → roda. NEEDS_APPROVAL → pede ao aprovador HITL (None ⇒ bloqueia).
        REJECT → recusa. Todo veredito é auditável (timeline + DecisionEntry)."""
        action = ProposedAction(
            tool=spec.name,
            target=target,
            capability=capability,
            impact_class=spec.metadata.impact_class,
        )
        decision = policy.vet(action)
        if decision.verdict is Verdict.EXECUTE:
            return True
        if decision.verdict is Verdict.NEEDS_APPROVAL:
            approved = self._approver is not None and self._approver.approve(action)
            verb = "aprovada (HITL)" if approved else "bloqueada (HITL — sem aprovação)"
            emitter.emit(ev.log(f"[política] {spec.name} → {target}: {verb} ← {decision.reason}"))
            decisions.append(
                DecisionEntry(
                    step=step_no,
                    capability=capability,
                    agent="",
                    action="approved" if approved else "blocked",
                    tool=spec.name,
                    detail=f"HITL: {decision.reason}",
                )
            )
            return approved
        # REJECT
        emitter.emit(ev.log(f"[política] {spec.name} → {target}: RECUSADA ← {decision.reason}"))
        decisions.append(
            DecisionEntry(
                step=step_no,
                capability=capability,
                agent="",
                action="rejected",
                tool=spec.name,
                detail=f"política: {decision.reason}",
            )
        )
        return False

    def _expand_targets(
        self,
        step_findings: list[Finding],
        *,
        working: list[str],
        working_hosts: set[str],
        scope: Scope,
        persp: Perspective,
        override: bool,
        budget_max: int,
        emitter: EventSink,
        state: ScanState,
    ) -> None:
        """Expansão de alvos dirigida por descoberta (ADR-0018): hosts/IPs/subdomínios
        descobertos viram NOVOS alvos das capacidades seguintes.

        Invariantes inegociáveis: cada candidato passa pelo **gate de escopo** ANTES
        de entrar (fora do escopo é descartado, §3.2), há **dedup** contra o que já
        está no working-set, e um **teto duro** (`Budget.max_targets`) impede
        explosão. Só o que a ferramenta REALMENTE reportou vira alvo (§3.1) — nada
        inventado. Cada admissão é auditável na timeline ("novo alvo: X ← Y")."""
        from ...perspective import extract_host

        for f in step_findings:
            if len(working) >= budget_max:
                return  # teto duro atingido — não expande mais (anti-explosão)
            raw = (f.affected_asset or "").strip()
            if not raw:
                continue
            host = extract_host(raw)
            if not host:
                continue
            key = host.lower()
            if key in working_hosts:
                continue  # dedup: já é alvo (original ou descoberto)
            # Gate de escopo ANTES de escanear (defesa em profundidade, §3.2/§3.3):
            # perspectiva, metadata-SSRF e (na trava dura) pertencimento. Fora → descarta.
            try:
                scope.enforce(host, perspective=persp, override=override)
            except ScopeViolation as exc:
                emitter.emit(
                    ev.log(f"[expansão] alvo descoberto FORA de escopo, descartado: {host} ({exc})")
                )
                continue
            working.append(host)
            working_hosts.add(key)
            state.discovered_targets.add(host)
            emitter.emit(ev.log(f"[expansão] novo alvo: {host} ← {f.source_tool} ({f.title[:50]})"))

    def _persist_incremental(
        self, scan_id: Optional[int], step_findings: list[Finding], state: ScanState
    ) -> None:
        """Grava as descobertas da onda e o progresso — durável contra kill/timeout.

        Idempotente: o UPSERT do store (UNIQUE scan_id,fingerprint) evita duplicar;
        o _finalize regrava a versão pontuada por cima. Nunca derruba o scan: uma
        falha de escrita é logada e o loop continua (a coleta é mais importante)."""
        if self._store is None or scan_id is None:
            return
        try:
            if step_findings:
                self._store.add_findings(scan_id, step_findings)
            self._store.set_executed_capabilities(
                scan_id, [c.value for c in state.executed_capabilities]
            )
        except Exception as exc:  # noqa: BLE001 — persistência parcial não derruba o scan
            import logging

            logging.getLogger("eigan.cognitive.engine").warning(
                "persistência incremental falhou (scan %s): %s", scan_id, exc
            )

    def _finalize(
        self,
        goal: Goal,
        scan_id: Optional[int],
        state: ScanState,
        decisions: list[DecisionEntry],
        stop_reason: StopReason,
        emitter: EventSink,
    ) -> CognitiveReport:
        findings = deduplicate(state.findings)
        # Validação (§16): confiança explícita e grounded — sobe só com prova (PoC
        # ativa) ou corroboração (≥2 fontes); nunca fabrica. Após o dedup (que popula
        # correlated_sources) e antes do risco.
        from ...analysis.validation import Validator

        validation = Validator().apply(findings)
        if self._risk is not None:
            findings = self._risk.score(findings)
        findings.sort(key=lambda f: (f.risk_rank, f.severity.rank), reverse=True)

        # Observabilidade (§22, ADR-0025): consolida o uso de tokens do loop cognitivo.
        usage = self._scan_meter.total()
        by_model = self._scan_meter.by_model()
        ai_calls = self._scan_meter.call_count()
        usage_payload = {**usage.as_dict(), "calls": ai_calls}
        by_model_payload = {k: v.as_dict() for k, v in by_model.items()}

        if self._store is not None and scan_id is not None:
            self._store.add_findings(scan_id, findings)
            if ai_calls:
                self._store.set_token_usage(
                    scan_id, {"total": usage_payload, "by_model": by_model_payload}
                )
            self._store.finish_scan(scan_id)

        decisions.append(
            DecisionEntry(
                step=state.steps_executed,
                capability="",
                agent="",
                action="stop",
                detail=stop_reason.value,
            )
        )
        emitter.emit(
            ev.analysis_complete(
                {
                    "findings": len(findings),
                    "capabilities": state.steps_executed,
                    "suggestions": len(state.suggestions),
                    "stop": stop_reason.value,
                    "validation": validation.as_dict(),
                }
            )
        )
        if ai_calls:
            emitter.emit(ev.token_usage(usage_payload, by_model_payload))
        emitter.emit(ev.scan_status(scan_id, "completed"))
        return CognitiveReport(
            goal=goal,
            scan_id=scan_id,
            findings=findings,
            decisions=decisions,
            stop_reason=stop_reason,
            planner_name=self._planner.name,
            ai_used=bool(getattr(self._planner, "ai_generated", False)),
            suggestions=list(state.suggestions),
            discovered_targets=sorted(state.discovered_targets),
            token_usage=usage,
            ai_calls=ai_calls,
            token_usage_by_model=by_model,
        )

    def _ai_budget_stop(self, budget: Budget) -> Optional[StopReason]:
        """Teto de IA (§2.1): encerra o loop ao atingir tokens/custo acumulados.

        O teto de TOKEN é sempre confiável (medido do provedor). O de CUSTO só é
        aplicado quando TODAS as chamadas têm preço verificado (``config/ai_pricing.yaml``);
        senão o custo total é UNVERIFIED e o teto de token é o piso (P1 — nunca estima)."""
        if budget.max_ai_tokens is not None:
            if self._scan_meter.total().total_tokens >= budget.max_ai_tokens:
                return StopReason.BUDGET_TOKENS
        if budget.max_ai_cost_usd is not None:
            cost = self._verified_cost_usd()
            if cost is not None and cost >= budget.max_ai_cost_usd:
                return StopReason.BUDGET_COST
        return None

    def _verified_cost_usd(self) -> Optional[float]:
        """Custo total só quando TODAS as chamadas têm preço verificado; senão None."""
        total = 0.0
        for usage_event in self._scan_meter.events:
            estimate = self._cost_model.cost_for(usage_event.model, usage_event.usage)
            if estimate is None:
                return None
            total += estimate.amount
        return total

    def _base_context(self, goal: Goal) -> SelectionContext:
        prefer = _PREFER_BY_PROFILE.get(goal.profile, Prefer.BALANCED)
        return SelectionContext(
            perspective=goal.perspective,
            tags=frozenset({goal.perspective.value}),
            prefer=prefer,
        )
