# ADR-0058 — Export nativo para SIEM em CEF (§16.2)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §16.2

## Contexto

O EIGAN já exporta SARIF, mas SIEMs comuns (ArcSight e outros) ingerem **CEF** (Common
Event Format). Faltava um exportador CEF determinístico que siga a especificação oficial,
sem fabricar esquema (P1).

## Decisão

Adicionar `eigan.integrations.siem`:

- `finding_to_cef(finding)` / `to_cef(findings)` — geram linhas CEF válidas: cabeçalho de
  7 campos (`CEF:0|EIGAN|EIGAN|<versão>|<sig>|<nome>|<sev 0–10>`) + extensão em pares
  `chave=valor`, com as **regras de escape** oficiais (`\` e `|` no cabeçalho; `\`, `=` e
  nova linha na extensão). Determinístico (ordem fixa de campos) e reprodutível.
- Severidade mapeada para a escala CEF 0–10; a versão vem de `__version__` (fonte única,
  sem drift).
- Campos textuais são **redigidos** (`ai.sanitize.redact`) para não vazar segredo/PII nos
  logs do SIEM (P8).

## Consequências

- **Positivas:** findings ingeríveis por SIEM comum em formato oficial e reprodutível;
  reusa a redaction unificada (§11.2); complementa o SARIF existente.
- **Custos/limites:** outros formatos (LEEF/ECS) e o transporte (syslog/HTTP) entram
  conforme necessidade; o schema versionado dos exports liga ao §24.2.
- **Originalidade (P7):** implementação própria seguindo a spec pública do CEF; nada de
  terceiro copiado.
