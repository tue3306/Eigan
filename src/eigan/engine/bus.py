"""Event Bus — publicação/assinatura in-process, síncrona (ADR-0026).

Hoje o Core emite eventos por um único :class:`~eigan.engine.events.EventSink`
(o broadcaster WS). Conforme a plataforma cresce (§11 agentes colaboram por
eventos; §13 estágios do pipeline publicam; §22 métricas observam), um evento
precisa chegar a **vários** consumidores sem acoplar o produtor a cada um.

O :class:`EventBus` resolve isso com o **mínimo que funciona** (§4.4 — sem broker,
sem fila assíncrona, sem persistência): é ele próprio um ``EventSink``, então entra
em qualquer ``sink=`` existente, e faz *fan-out* síncrono para N assinantes, com
filtro opcional por ``type`` do evento.

**Semântica de erro (importante):** o bus **não engole** exceções dos assinantes —
o cancelamento cooperativo de scan depende de um sink levantar (``ScanCancelled``).
Assinantes auxiliares (logging/métricas) devem ser **não-levantadores**; assine-os
antes do sink primário para que observem o evento mesmo que o primário aborte.

Inspiração conceitual: o desacoplamento produtor→consumidor por eventos do Wazuh;
implementação 100% original e propositalmente enxuta.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Any

from .events import EventSink


class EventBus:
    """Fan-out síncrono de eventos para assinantes (cada um é um ``EventSink``)."""

    def __init__(self, *initial: EventSink) -> None:
        # (tipos_ou_None, sink) — tipos=None ⇒ recebe todos os eventos.
        self._subs: list[tuple[frozenset[str] | None, EventSink]] = []
        self._lock = threading.Lock()
        for sink in initial:
            self.subscribe(sink)

    def subscribe(self, sink: EventSink, *, types: Iterable[str] | None = None) -> EventSink:
        """Registra ``sink``; se ``types`` for dado, só recebe esses ``event["type"]``.

        Devolve o próprio ``sink`` para encadear. A ordem de assinatura é a ordem de
        entrega — assine consumidores auxiliares antes de sinks que possam abortar."""
        selector = frozenset(types) if types is not None else None
        with self._lock:
            self._subs.append((selector, sink))
        return sink

    def emit(self, event: dict[str, Any]) -> None:
        """Entrega ``event`` a cada assinante interessado, em ordem de assinatura.

        Não captura exceções: um sink que levanta (ex.: cancelamento cooperativo)
        interrompe a entrega — por isso o cancelamento continua funcionando com o
        bus no lugar do sink direto."""
        etype = event.get("type", "")
        for selector, sink in self._snapshot():
            if selector is None or etype in selector:
                sink.emit(event)

    def _snapshot(self) -> list[tuple[frozenset[str] | None, EventSink]]:
        with self._lock:
            return list(self._subs)

    def __len__(self) -> int:
        return len(self._snapshot())
