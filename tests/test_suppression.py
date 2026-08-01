"""Marcação de finding e supressão versionada (§13.1).

Falha antes / passa depois: uma regra exige decisão humana + matcher; casa por
ativo/CWE/fingerprint/título; expira; e ao aplicar, o finding suprimido NÃO some — é
marcado com o veredito e a referência da decisão (P2). Digest determinístico; YAML.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from eigan.findings.schema import Finding, FindingStatus, Severity
from eigan.findings.suppression import (
    InvalidSuppressionRule,
    SuppressionRule,
    SuppressionSet,
)

_NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _finding(**kw) -> Finding:
    base = dict(
        title="TLS fraco", severity=Severity.MEDIUM, affected_asset="10.0.0.1", source_tool="x"
    )
    base.update(kw)
    return Finding(**base)


def _rule(**kw) -> SuppressionRule:
    base = dict(
        rule_id="r1",
        verdict=FindingStatus.FALSE_POSITIVE,
        decided_by="analista",
        reference="TICKET-42",
    )
    base.update(kw)
    return SuppressionRule(**base)


def test_rule_requires_human_decision() -> None:
    with pytest.raises(InvalidSuppressionRule):
        _rule(decided_by="", asset="*")
    with pytest.raises(InvalidSuppressionRule):
        _rule(reference="", asset="*")


def test_rule_requires_at_least_one_matcher() -> None:
    with pytest.raises(InvalidSuppressionRule):
        _rule()  # nenhum matcher → recusado (não suprimir tudo)


def test_verdict_must_be_a_suppressing_status() -> None:
    with pytest.raises(InvalidSuppressionRule):
        _rule(verdict=FindingStatus.OPEN, asset="*")


def test_matches_by_asset_glob_cwe_and_title() -> None:
    rule = _rule(asset="10.0.0.*", cwe="CWE-326", title_contains="tls")
    assert rule.matches(_finding(cwe="CWE-326"), now=_NOW) is True
    assert rule.matches(_finding(cwe="CWE-89"), now=_NOW) is False  # CWE difere
    assert rule.matches(_finding(affected_asset="192.168.0.1", cwe="CWE-326"), now=_NOW) is False


def test_matches_by_fingerprint() -> None:
    f = _finding(cwe="CWE-89")
    rule = _rule(fingerprint=f.fingerprint)
    assert rule.matches(f, now=_NOW) is True
    assert rule.matches(_finding(affected_asset="outro", cwe="CWE-89"), now=_NOW) is False


def test_expired_rule_does_not_match() -> None:
    rule = _rule(asset="*", expires_at=_NOW - timedelta(seconds=1))
    assert rule.matches(_finding(), now=_NOW) is False


def test_apply_marks_but_never_removes() -> None:
    findings = [_finding(cwe="CWE-326"), _finding(affected_asset="9.9.9.9", cwe="CWE-89")]
    rules = SuppressionSet([_rule(asset="10.0.0.*")])
    outcomes = rules.apply(findings, now=_NOW)
    assert len(outcomes) == len(findings)  # nada foi removido
    assert outcomes[0].suppressed is True
    assert "TICKET-42" in outcomes[0].note
    assert outcomes[0].marked().status is FindingStatus.FALSE_POSITIVE
    # o finding original permanece OPEN (a marcação é uma cópia)
    assert findings[0].status is FindingStatus.OPEN
    # o segundo finding não casou nenhuma regra
    assert outcomes[1].suppressed is False
    assert outcomes[1].marked().status is FindingStatus.OPEN


def test_accepted_risk_verdict() -> None:
    rules = SuppressionSet([_rule(verdict=FindingStatus.ACCEPTED_RISK, asset="*")])
    outcome = rules.apply([_finding()], now=_NOW)[0]
    assert outcome.marked().status is FindingStatus.ACCEPTED_RISK


def test_digest_deterministic_and_sensitive() -> None:
    a = SuppressionSet([_rule(asset="10.0.0.*")])
    b = SuppressionSet([_rule(asset="10.0.0.*")])
    assert a.digest() == b.digest()
    c = SuppressionSet([_rule(asset="10.0.0.5")])
    assert a.digest() != c.digest()


def test_dict_round_trip() -> None:
    original = SuppressionSet(
        [_rule(asset="10.0.0.*", cwe="CWE-326", reason="cert interno conhecido")]
    )
    restored = SuppressionSet.from_dict(original.to_dict())
    assert restored.digest() == original.digest()
    assert restored.rules[0].decided_by == "analista"
