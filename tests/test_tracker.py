"""Propostas de item de trabalho deduplicadas (§16.3).

Falha antes / passa depois: findings da mesma classe viram UMA proposta com os ativos
agregados; filtro por severidade; nada abaixo do limiar; redaction; ordenação; proposta
(não criação).
"""

from __future__ import annotations

from eigan.findings.schema import Finding, Severity
from eigan.integrations.tracker import propose_work_items


def _f(asset: str, cwe: str = "CWE-326", sev: Severity = Severity.HIGH, title: str = "TLS fraco"):
    return Finding(title=title, severity=sev, affected_asset=asset, source_tool="testssl", cwe=cwe)


def test_same_class_dedups_into_one_proposal() -> None:
    findings = [_f("10.0.0.1"), _f("10.0.0.2"), _f("10.0.0.3")]  # 3 instâncias, 1 classe
    proposals = propose_work_items(findings)
    assert len(proposals) == 1
    p = proposals[0]
    assert p.count == 3
    assert p.affected_assets == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]  # ativos agregados


def test_different_classes_get_separate_proposals() -> None:
    findings = [_f("a", cwe="CWE-326"), _f("b", cwe="CWE-89", title="SQLi")]
    assert len(propose_work_items(findings)) == 2


def test_severity_threshold() -> None:
    findings = [_f("a", sev=Severity.LOW), _f("b", sev=Severity.CRITICAL, cwe="CWE-89")]
    proposals = propose_work_items(findings, min_severity=Severity.HIGH)
    assert len(proposals) == 1
    assert proposals[0].severity is Severity.CRITICAL


def test_labels_and_redaction() -> None:
    p = propose_work_items([_f("http://x?token=SECRETO", title="token=LEAK")])[0]
    assert "SECRETO" not in str(p.affected_assets)
    assert "LEAK" not in p.title
    assert "severity:high" in p.labels
    assert "tool:testssl" in p.labels


def test_sorted_by_severity() -> None:
    findings = [
        _f("a", cwe="CWE-326", sev=Severity.MEDIUM),
        _f("b", cwe="CWE-89", sev=Severity.CRITICAL, title="SQLi"),
    ]
    proposals = propose_work_items(findings)
    assert proposals[0].severity is Severity.CRITICAL


def test_empty() -> None:
    assert propose_work_items([]) == []
