"""Fila de aprovação humana — HITL operacional (§19.5).

Ações de alto impacto que a política marca ``NEEDS_APPROVAL`` (ADR-0011) ficam
pendentes **com contexto** (o quê, contra qual alvo, qual capacidade, classe de
impacto, justificativa), e um humano aprova/rejeita. **Fail-safe (P9):** sem um
decisor humano, a ação é **rejeitada** — nenhuma ação de alto impacto executa sem
aprovação humana **registrada**. Toda decisão entra numa fila **auditável**.

Implementa a porta ``ApprovalPort`` (o `CognitiveEngine` a consome); um ``decide``
opcional liga o CLI (pergunta ao operador) ou a API (aprovação sob consent auditado).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .engine import ProposedAction


@dataclass(frozen=True)
class ApprovalRecord:
    """Registro auditável de um pedido de aprovação HITL e sua decisão."""

    tool: str
    target: str
    capability: str
    impact_class: str
    approved: bool
    reason: str


@dataclass
class HITLQueue:
    """Trilha auditável dos pedidos de aprovação de alto impacto e suas decisões."""

    records: list[ApprovalRecord] = field(default_factory=list)

    def add(self, action: ProposedAction, *, approved: bool, reason: str) -> ApprovalRecord:
        record = ApprovalRecord(
            tool=action.tool,
            target=action.target,
            capability=action.capability,
            impact_class=getattr(action.impact_class, "value", str(action.impact_class)),
            approved=approved,
            reason=reason,
        )
        self.records.append(record)
        return record

    @property
    def approved(self) -> list[ApprovalRecord]:
        return [r for r in self.records if r.approved]

    @property
    def rejected(self) -> list[ApprovalRecord]:
        return [r for r in self.records if not r.approved]


class FailSafeApprover:
    """``ApprovalPort`` com fail-safe (§19.5).

    Sem ``decide`` (nenhum decisor humano disponível), **rejeita** toda ação — o
    default seguro, equivalente a "timeout de aprovação = rejeição". Um ``decide``
    (CLI pergunta ao operador; API sob consent auditado) pode aprovar. **Toda** decisão
    é registrada na fila com o contexto da ação — a prova de que o alto impacto só
    executou sob aprovação humana."""

    def __init__(
        self,
        queue: HITLQueue | None = None,
        decide: Callable[[ProposedAction], bool] | None = None,
    ) -> None:
        self.queue = queue if queue is not None else HITLQueue()
        self._decide = decide

    def approve(self, action: ProposedAction) -> bool:
        if self._decide is None:
            self.queue.add(
                action, approved=False, reason="sem decisor humano → fail-safe: rejeitada"
            )
            return False
        approved = bool(self._decide(action))
        self.queue.add(
            action, approved=approved, reason="aprovada (HITL)" if approved else "rejeitada (HITL)"
        )
        return approved
