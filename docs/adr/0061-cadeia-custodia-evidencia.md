# ADR-0061 — Cadeia de custódia da evidência (§21.1)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §21.1

## Contexto

Um achado só é defensável se a evidência que o sustenta for **íntegra**. Sem um selo na
coleta, não há como provar que a saída de ferramenta / prova de validação não foi alterada
depois — o que fragiliza discussão contratual, remediação disputada e auditoria.

## Decisão

Adicionar `eigan.findings.evidence`:

- `seal_evidence(content, source=, at=)` — calcula o **SHA-256** e carimba a **data** de
  coleta, devolvendo um `EvidenceRecord` (hash, `collected_at`, `source`, `size`),
  serializável para a trilha de auditoria (§18.3).
- `verify_evidence(record, content)` — confere se o conteúdo corresponde ao selo
  (evidência não alterada), incluindo tamanho.

Determinístico (data injetada). **Honestidade (P1/P2):** o selo garante que a evidência
**armazenada** (já redigida, P8/§11.2) não foi alterada após a coleta — não afirmamos
reconstruir o original em claro, que não é retido.

## Consequências

- **Positivas:** toda evidência ganha hash e data verificáveis; combinado com a trilha
  (o hash entra na trilha), a alteração posterior é detectável; base para o pacote de
  evidência por finding (§21.2) e o relatório reproduzível (§21.3).
- **Custos/limites:** a coleta do selo no fluxo de scan (o runner selar a saída) é
  incremento seguinte; a primitiva já está aqui e testada.
- **Originalidade (P7):** implementação própria com stdlib; nada de terceiro copiado.
