# ADR-0043 — Contrato versionado do Finding (JSON Schema publicável)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §24.2

## Contexto

A API é `/api/v1` e há exports (SARIF/JSON/CSV) que outros sistemas (SIEM/CI) consomem.
Sem um contrato **versionado e validado**, cada mudança no `Finding` quebra integração de
cliente em silêncio — o jeito mais rápido de perder confiança corporativa.

## Decisão

Adicionar `eigan.findings.contract`:

- **`finding_json_schema()`** — devolve o JSON Schema do `Finding` **gerado do próprio
  modelo Pydantic** (nunca escrito à mão e desatualizado, P1/P2), carimbado com `$id` e
  `x-contract-version`.
- **`FINDING_SCHEMA_VERSION`** — versão do **contrato de dados**, independente da versão
  do produto; sobe deliberadamente quando o contrato muda de forma quebrante.
- **`GUARANTEED_FIELDS`** — o conjunto de campos que o contrato garante aos consumidores.
- Teste de contrato: o schema é gerado, versionado, contém todos os campos garantidos, e
  o `severity` expõe o enum fechado (o consumidor sabe os valores possíveis). Remover um
  campo garantido **quebra o teste** — a mudança fica explícita e exige bump de versão.

## Consequências

- **Positivas:** consumidores sabem exatamente o que esperar; mudança quebrante é
  deliberada e versionada; o schema nunca desatualiza (gerado do modelo). Base para a
  política de depreciação (§24.1) e o snapshot de exports (§14.2).
- **Custos/limites:** o schema publicado é **gerado sob demanda** por
  `finding_json_schema()` (evita um arquivo estático que derivaria com versões do
  Pydantic); a validação de instâncias com `jsonschema` fica opcional (sem adicionar
  dependência ao caminho padrão — restrição #7). Os schemas dos formatos de export
  (SARIF/CSV) seguem a mesma ideia em incremento seguinte.
- **Originalidade (P7):** contrato próprio; nada de terceiro copiado.
