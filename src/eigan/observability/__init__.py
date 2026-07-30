"""Observabilidade do EIGAN (ADR-0025).

Nasce **com** a camada de IA, não como retrofit: instrumenta uso de tokens e
custo de execução — a base para governança de custo de um produto AI-native.

* :mod:`eigan.observability.usage` — contagem **real** de tokens (extraída da
  resposta de cada provedor) num medidor thread-safe e escopável por execução.
* :mod:`eigan.observability.cost` — tokens → custo usando uma tabela de preços
  **verificada pelo operador**. Preço de LLM é dado factual que muda; por §2/§5 o
  EIGAN **nunca fabrica preço** — sem entrada verificada, o custo é `UNVERIFIED`.

Regra de ouro: observabilidade é **best-effort** e **nunca** derruba um scan.
"""

from __future__ import annotations

from .cost import CostEstimate, CostModel
from .metrics import MetricsCollector
from .usage import (
    TokenUsage,
    UsageEvent,
    UsageMeter,
    current_meter,
    extract_usage,
    record_completion,
    use_meter,
)

__all__ = [
    "TokenUsage",
    "UsageEvent",
    "UsageMeter",
    "current_meter",
    "extract_usage",
    "record_completion",
    "use_meter",
    "CostEstimate",
    "CostModel",
    "MetricsCollector",
]
