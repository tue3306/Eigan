# ADR-0059 — Propostas de item de trabalho deduplicadas (§16.3)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §16.3

## Contexto

Levar findings ao fluxo do time exige criar itens de trabalho (tickets) — mas abrir 50
tickets do mesmo problema é ruído, e criar ticket é ação **irreversível** que não pode ser
automática (P9).

## Decisão

Adicionar `eigan.integrations.tracker`:

- `WorkItemProposal` — proposta revisável que agrega os findings de **uma classe**
  (mesmo CWE/título), com ativos afetados, ferramentas, contagem e `labels`.
- `propose_work_items(findings, min_severity=)` — filtra por severidade e **deduplica por
  classe** (liga ao dedup semântico §2.4): 50 instâncias de "TLS fraco" → **uma** proposta
  listando os ativos. Campos textuais redigidos (P8). Devolve **propostas**, nunca cria
  ticket (P9) — a criação fica com o humano/adaptador.

## Consequências

- **Positivas:** findings viram propostas acionáveis e deduplicadas, sem ruído de tickets
  repetidos; nada irreversível automático; reusa a redaction unificada.
- **Custos/limites:** o adaptador que efetiva a criação (Jira/GitHub Issues via API, com
  credencial de ambiente — P4) é incremento seguinte, sempre a partir de uma proposta
  aprovada.
- **Originalidade (P7):** implementação própria; nada de terceiro copiado.
