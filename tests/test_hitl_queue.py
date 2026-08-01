"""Fila de aprovação humana HITL (§19.5): fail-safe + trilha auditável."""

from __future__ import annotations

from eigan.policy.approval import FailSafeApprover, HITLQueue
from eigan.policy.engine import ProposedAction
from eigan.policy.impact import ImpactClass


def _action() -> ProposedAction:
    return ProposedAction(
        tool="sqlmap",
        target="10.0.0.5",
        capability="exploitation",
        impact_class=ImpactClass.EXPLOIT_VALIDATION,
    )


def test_failsafe_rejects_without_human_decider() -> None:
    q = HITLQueue()
    approver = FailSafeApprover(q)  # sem decisor → fail-safe
    assert approver.approve(_action()) is False
    assert len(q.rejected) == 1 and not q.approved
    rec = q.rejected[0]
    assert rec.tool == "sqlmap" and rec.impact_class == "exploit_validation"
    assert "fail-safe" in rec.reason  # decisão registrada com contexto


def test_human_approval_recorded() -> None:
    q = HITLQueue()
    approver = FailSafeApprover(q, decide=lambda a: True)
    assert approver.approve(_action()) is True
    assert len(q.approved) == 1 and q.approved[0].capability == "exploitation"
    assert "HITL" in q.approved[0].reason


def test_human_rejection_recorded() -> None:
    q = HITLQueue()
    approver = FailSafeApprover(q, decide=lambda a: False)
    assert approver.approve(_action()) is False
    assert len(q.rejected) == 1 and "rejeitada (HITL)" in q.rejected[0].reason


def test_is_approval_port_for_engine() -> None:
    # É um ApprovalPort válido (tem approve(action) -> bool) — plugável no engine.
    approver = FailSafeApprover()
    result = approver.approve(_action())
    assert isinstance(result, bool)
    assert len(approver.queue.records) == 1  # tudo auditado, mesmo a rejeição fail-safe
