# ADR-0044 — Orçamentos de tempo e recurso por ferramenta

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §12.4

## Contexto

O `Budget` do goal limita o scan como um todo (tempo/alvos/custo), e o runner tem um
timeout por chamada. Faltava a fronteira **por ferramenta** com duas garantias: uma
ferramenta lenta não consome o scan inteiro, e a **saída** de uma ferramenta que processa
dado potencialmente hostil não cresce sem limite — contenção de parser malicioso (liga ao
§7.2, onde o fuzzing achou crashes por saída patológica).

## Decisão

Adicionar `eigan.engine.toolbudget` com primitivas puras e testáveis:

- **`Deadline`** — prazo de parede por ferramenta com relógio injetável; `remaining()`,
  `expired()` e `timeout_arg()` (o restante, nunca negativo, para passar ao subprocess).
- **`cap_output(text, max_bytes)`** — corta a saída no teto de bytes **sem partir um
  caractere UTF-8** (decode do prefixo com `errors='ignore'`), sinaliza truncamento e
  preserva o tamanho original (transparência — P2).
- **`ToolLimits`** — configuração combinada (tempo + tamanho de saída) por ferramenta,
  validada.

## Consequências

- **Positivas:** base para o runner impor prazo/tamanho por ferramenta sem que uma
  ferramenta isolada esgote o orçamento global; o corte de saída fecha um vetor de
  parser malicioso de forma determinística; tudo testável sem subprocess real.
- **Custos/limites (honestos):** o **wiring** no runner (`engine/base.py` usar
  `Deadline.timeout_arg()` e `ToolLimits.cap()` na captura de stdout) é incremento
  seguinte — este ADR entrega as primitivas para não alterar o comportamento do runner
  agora e evitar regressão. Limite de **memória** é dependente de SO (POSIX `setrlimit`;
  Windows sem equivalente direto) e não é fabricado (P1) — fica para o wiring por
  plataforma.
- **Originalidade (P7):** implementação própria com stdlib; nada de terceiro copiado.
