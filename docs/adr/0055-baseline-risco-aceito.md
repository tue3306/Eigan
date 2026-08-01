# ADR-0055 — Baseline de risco aceito por engajamento (§13.2)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §13.2

## Contexto

Um engajamento tem exposições **conhecidas e autorizadas** (risco aceito) que não devem
re-alertar como novidade a cada scan. Sem um baseline, o relatório repete o já aceito e
esconde o que realmente mudou — ruído que corrói a confiança. Complementa a supressão de
FP (§13.1, ADR-0038): supressão remove FP do fluxo; baseline separa o **aceito** do
**novo**.

## Decisão

Adicionar `eigan.findings.baseline`:

- `BaselineEntry` — um `fingerprint` aceito com a decisão que o autorizou (`decided_by` +
  `reference` **obrigatórios** — decisão humana, P9).
- `Baseline` — conjunto versionado; `accept(finding, …)` registra a aceitação;
  `partition(findings)` devolve `BaselineResult` com **novos** (fora do baseline),
  **aceitos** (já no baseline) e **resolvidos** (estavam no baseline e sumiram);
  `digest()`/`to_dict`/`from_dict` para versionar/persistir.

Reusa `Finding.fingerprint` (P6). O relatório passa a destacar `result.changed` — novos e
resolvidos — em vez de repetir o aceito.

## Consequências

- **Positivas:** reduz ruído sem esconder mudança; o operador vê o que é novo desde o
  baseline e o que foi resolvido; aceitações auditáveis e reversíveis (remover a entrada);
  liga ao diff (pilar 2) e à supressão (§13.1).
- **Custos/limites:** a aplicação no pipeline de relatório e a persistência por engajamento
  são incremento seguinte; a primitiva já está aqui e testada.
- **Originalidade (P7):** modelo próprio; nada de terceiro copiado.
