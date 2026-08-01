"""Notificações/webhooks acima de um limiar de severidade (§16.1).

Emite eventos de finding para um canal externo (webhook) quando a severidade cruza um
limiar. Segue os princípios: **redaction** no payload (P8, reusa `ai.sanitize.redact`) e
**nenhum segredo no repositório** (P4 — a URL/token do webhook vem do ambiente, não daqui).

O transporte é um **sink injetável** (`Callable[[dict], None]`): o núcleo constrói e
filtra o payload de forma pura e testável; o adaptador HTTP real (com httpx, extra
opcional) é plugado por fora, mantendo o caminho padrão sem dependência de rede.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..ai.sanitize import redact
from ..findings.schema import Finding, Severity

# Sink: recebe um payload já redigido e o entrega (HTTP, fila, arquivo…).
WebhookSink = Callable[[dict[str, Any]], None]


def build_finding_payload(finding: Finding) -> dict[str, Any]:
    """Payload redigido de um finding para entrega externa (sem evidência bruta)."""
    return {
        "title": redact(finding.title),
        "severity": finding.severity.value,
        "affected_asset": redact(finding.affected_asset),
        "source_tool": finding.source_tool,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "status": finding.status.value,
        "fingerprint": finding.fingerprint,
    }


class WebhookNotifier:
    """Entrega findings acima de um limiar de severidade a um sink injetável."""

    def __init__(self, sink: WebhookSink, *, min_severity: Severity = Severity.HIGH) -> None:
        self._sink = sink
        self._min_rank = min_severity.rank

    def _qualifies(self, finding: Finding) -> bool:
        return finding.severity.rank >= self._min_rank

    def notify(self, findings: list[Finding]) -> int:
        """Entrega os findings que cruzam o limiar; devolve quantos foram entregues."""
        delivered = 0
        for finding in findings:
            if self._qualifies(finding):
                self._sink(build_finding_payload(finding))
                delivered += 1
        return delivered
