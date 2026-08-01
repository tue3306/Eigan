"""Baseline de risco aceito por engajamento (§13.2).

Falha antes / passa depois: aceitar exige decisão humana; partition separa novos/aceitos
e detecta resolvidos; digest determinístico; round-trip; changed reflete mudança.
"""

from __future__ import annotations

import pytest

from eigan.findings.baseline import Baseline, InvalidBaselineEntry
from eigan.findings.schema import Finding, Severity


def _f(asset: str, cwe: str = "CWE-89") -> Finding:
    return Finding(
        title="v", severity=Severity.HIGH, affected_asset=asset, source_tool="x", cwe=cwe
    )


def test_accept_requires_human_decision() -> None:
    b = Baseline()
    with pytest.raises(InvalidBaselineEntry):
        b.accept(_f("10.0.0.1"), decided_by="", reference="TICKET-1")
    with pytest.raises(InvalidBaselineEntry):
        b.accept(_f("10.0.0.1"), decided_by="ana", reference="")


def test_partition_separates_new_accepted_and_resolved() -> None:
    b = Baseline()
    known = _f("10.0.0.1")
    gone = _f("10.0.0.9")
    b.accept(known, decided_by="ana", reference="TICKET-1")
    b.accept(gone, decided_by="ana", reference="TICKET-2")

    current = [known, _f("10.0.0.2")]  # known (aceito) + um novo; 'gone' sumiu
    result = b.partition(current)
    assert [f.affected_asset for f in result.accepted] == ["10.0.0.1"]
    assert [f.affected_asset for f in result.new] == ["10.0.0.2"]
    assert result.resolved_fingerprints == [gone.fingerprint]
    assert result.changed is True


def test_no_change_when_only_accepted_present() -> None:
    b = Baseline()
    known = _f("10.0.0.1")
    b.accept(known, decided_by="ana", reference="T")
    result = b.partition([known])
    assert result.new == [] and result.resolved_fingerprints == []
    assert result.changed is False


def test_digest_deterministic_and_round_trip() -> None:
    b = Baseline()
    b.accept(_f("10.0.0.1"), decided_by="ana", reference="T1", note="cert interno")
    b.accept(_f("10.0.0.2"), decided_by="ana", reference="T2")
    restored = Baseline.from_dict(b.to_dict())
    assert restored.digest() == b.digest()
    assert len(restored.entries) == 2


def test_contains() -> None:
    b = Baseline()
    f = _f("10.0.0.1")
    assert b.contains(f) is False
    b.accept(f, decided_by="ana", reference="T")
    assert b.contains(f) is True
