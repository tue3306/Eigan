"""Ecossistema de integração do EIGAN (TIER 16) — webhooks, SIEM, rastreio.

Peças opcionais que levam o EIGAN para o fluxo real do time, sempre com redaction (P8) e
sem segredo no repositório (P4). O transporte concreto (HTTP) é um adaptador injetável —
o núcleo (construção de payload, filtro por severidade) é puro e testável.
"""

from .webhooks import WebhookNotifier, build_finding_payload

__all__ = ["WebhookNotifier", "build_finding_payload"]
