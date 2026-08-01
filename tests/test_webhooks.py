"""Notificações/webhooks acima de limiar (§16.1).

Falha antes / passa depois: só findings >= limiar são entregues; o payload é redigido
(sem segredo/PII); o sink recebe um payload por finding qualificado; contagem correta.
"""

from __future__ import annotations

from eigan.findings.schema import Finding, Severity
from eigan.integrations.webhooks import WebhookNotifier, build_finding_payload


def _f(sev: Severity, title: str = "v", asset: str = "10.0.0.1") -> Finding:
    return Finding(title=title, severity=sev, affected_asset=asset, source_tool="x")


def test_only_above_threshold_is_delivered() -> None:
    delivered: list[dict] = []
    notifier = WebhookNotifier(delivered.append, min_severity=Severity.HIGH)
    findings = [_f(Severity.LOW), _f(Severity.HIGH), _f(Severity.CRITICAL), _f(Severity.MEDIUM)]
    count = notifier.notify(findings)
    assert count == 2  # só HIGH e CRITICAL
    assert {p["severity"] for p in delivered} == {"high", "critical"}


def test_payload_is_redacted() -> None:
    payload = build_finding_payload(
        _f(Severity.HIGH, title="token=SECRETO123", asset="http://ana@example.com")
    )
    assert "SECRETO123" not in payload["title"]
    assert "ana@example.com" not in payload["affected_asset"]
    assert "[REDACTED]" in payload["title"]


def test_payload_has_no_raw_evidence_field() -> None:
    # o payload não carrega evidência bruta (pode conter segredo)
    payload = build_finding_payload(_f(Severity.HIGH))
    assert "evidence" not in payload
    assert set(payload) == {
        "title",
        "severity",
        "affected_asset",
        "source_tool",
        "cwe",
        "owasp",
        "status",
        "fingerprint",
    }


def test_empty_and_all_below_threshold() -> None:
    delivered: list[dict] = []
    notifier = WebhookNotifier(delivered.append, min_severity=Severity.CRITICAL)
    assert notifier.notify([]) == 0
    assert notifier.notify([_f(Severity.HIGH), _f(Severity.LOW)]) == 0
    assert delivered == []
