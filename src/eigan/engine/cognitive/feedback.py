"""Feedback contínuo, estado do scan e condição de parada (ADR-0007).

Após cada execução o :class:`CognitiveEngine` registra um :class:`Feedback` e o
:class:`ScanState` o absorve — acumulando findings, capacidades já executadas e
**tags de contexto** derivadas das descobertas (serviço/tecnologia) que realimentam
o Tool Selection Engine. A :class:`StopCondition` encerra o loop por orçamento ou
tempo; a exaustão de plano/ausência de evidência é decidida pelo engine.

Determinístico e serializável — o estado é parte do rastro auditável.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from ...capability import Capability
from ...findings.schema import Finding
from ..cascade import FindingFeatures
from .goal import Budget

# tecnologias reconhecidas por substring no título do finding (tags de contexto).
_TECH_KEYWORDS = ("wordpress", "joomla", "drupal", "nginx", "apache", "iis", "tomcat")
_HTTP_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888})
_TLS_PORTS = frozenset({443, 8443, 993, 995, 465})


def tags_from_findings(findings: list[Finding]) -> set[str]:
    """Extrai tags de contexto (serviço/tecnologia/http/tls) de forma determinística."""
    tags: set[str] = set()
    for f in findings:
        feat = FindingFeatures.of(f)
        if feat.service:
            tags.add(feat.service)
        if feat.port in _HTTP_PORTS:
            tags.add("http")
        if feat.port in _TLS_PORTS:
            tags.add("tls")
        title = f.title.lower()
        for kw in _TECH_KEYWORDS:
            if kw in title:
                tags.add(kw)
    return tags


@dataclass
class Feedback:
    """Resultado de uma execução, realimentado ao Planner/estado."""

    capability: Capability
    tool: str
    findings: list[Finding]
    duration: float
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error


@dataclass(frozen=True)
class Suggestion:
    """Ferramenta sugerida pela cascata mas não executada (honesto)."""

    tool: str
    reason: str


@dataclass
class ScanState:
    """Estado acumulado do loop cognitivo — o rastro que o replan consulta."""

    findings: list[Finding] = field(default_factory=list)
    executed_capabilities: set[Capability] = field(default_factory=set)
    executed_tools: set[str] = field(default_factory=set)
    context_tags: set[str] = field(default_factory=set)
    suggestions: list[Suggestion] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)  # desde o último replan
    # Alvos DESCOBERTOS pela recon e realimentados como novos alvos (ADR-0018) —
    # só para auditoria/relatório; o working-set de execução vive no engine.
    discovered_targets: set[str] = field(default_factory=set)
    steps_executed: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def absorb(self, fb: Feedback) -> None:
        self.executed_capabilities.add(fb.capability)
        if fb.tool:
            self.executed_tools.add(fb.tool.lower())
        if fb.success and fb.tool:
            self.steps_executed += 1
        for f in fb.findings:
            self.findings.append(f)
            self.new_findings.append(f)
        self.context_tags |= tags_from_findings(fb.findings)

    def note_suggestion(self, tool: str, reason: str) -> None:
        if not any(s.tool == tool for s in self.suggestions):
            self.suggestions.append(Suggestion(tool=tool, reason=reason))

    def mark_replanned(self) -> None:
        """Consome as descobertas recentes após um replan (evita reprocessar)."""
        self.new_findings = []

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at


class StopReason(str, Enum):
    PLAN_EXHAUSTED = "plano concluído"
    NO_NEW_EVIDENCE = "sem nova evidência"
    BUDGET_CAPABILITIES = "limite de capacidades atingido"
    WALL_TIME = "limite de tempo atingido"
    BUDGET_TOKENS = "limite de tokens de IA atingido"
    BUDGET_COST = "limite de custo de IA atingido"
    MANUAL = "interrompido"


@dataclass
class StopCondition:
    """Avalia limites do :class:`Budget`. Exaustão de plano é decidida no engine."""

    budget: Budget

    def check(self, state: ScanState) -> StopReason | None:
        if state.steps_executed >= self.budget.max_capabilities:
            return StopReason.BUDGET_CAPABILITIES
        if (
            self.budget.max_wall_seconds is not None
            and state.elapsed() >= self.budget.max_wall_seconds
        ):
            return StopReason.WALL_TIME
        return None
