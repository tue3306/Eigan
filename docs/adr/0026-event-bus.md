# ADR-0026 — Event Bus in-process (fan-out síncrono de eventos)

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** módulo event-bus; agentes colaboram por eventos (nunca chamada
  acoplada); estágios do pipeline publicam; métricas observam eventos — roadmap de
  plataforma; CLAUDE.md §6/§18 (event-driven); ADR-0004 (EventSink)
- **Inspiração conceitual:** o desacoplamento produtor→consumidor por eventos do
  **Wazuh** (pipeline de eventos plugável). Implementação 100% original e enxuta;
  **nenhum código** de terceiros reutilizado (originalidade — princípio do EIGAN).

## Contexto

O Core emitia eventos para um **único** `EventSink` (o broadcaster WebSocket).
À medida que a plataforma cresce, um evento precisa chegar a **vários** consumidores
(dashboard, métricas ao vivo, futuros agentes colaborando, estágios de detecção)
sem acoplar o produtor a cada um. Ao mesmo tempo, um broker/fila assíncrona seria
over-engineering agora (§4.4): não há necessidade de durabilidade nem de cruzar
processos — os consumidores vivem no mesmo processo do scan.

## Decisão

`engine/bus.py`: `EventBus` é um `EventSink` que faz **fan-out síncrono in-process**
para N assinantes, com **filtro opcional por `type`** de evento. Por ser um
`EventSink`, entra em qualquer `sink=` já existente sem mudar o Core.

**Semântica de erro deliberada:** o bus **não captura** exceções dos assinantes —
o cancelamento cooperativo de scan depende de um sink levantar (`ScanCancelled`).
Assinantes auxiliares (métricas/logging) são **não-levantadores** por contrato e
assinados **antes** do sink primário, então observam o evento mesmo que o primário
aborte.

Primeiro consumidor real (evita código morto, §24): `observability/metrics.py`
`MetricsCollector` — assina o bus e agrega, ao vivo, eventos por tipo, execuções de
ferramenta por status, descobertas e uso de tokens. O `ScanManager` roda cada scan
por um `EventBus(metrics, job_sink)` e expõe `metrics.snapshot()` em `job.summary()`.

## Consequências

- **Positivas:** produtor desacoplado de N consumidores; base pronta para agentes
  (§11) e pipeline de eventos (§13) publicarem/assinarem; métricas ao vivo (§19/§22)
  sem tocar o engine. Mínimo que funciona — sem broker.
- **Custos/limites:** síncrono e in-process (por design). Se um dia houver
  necessidade real de assíncrono/durável/multi-processo, troca-se a implementação
  atrás do mesmo contrato `EventSink` — sem reescrever produtores.
- **Testes:** `tests/test_bus.py` cobre fan-out, filtro por tipo, a não-captura de
  exceções (cancelamento preservado) e a agregação de métricas.
