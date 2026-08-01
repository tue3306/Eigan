# ADR-0036 — Redaction de segredo/PII num ponto único (`ai/sanitize.py`)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §11.2

## Contexto

A política de remoção de segredo/PII estava **duplicada**: `ai/provider.py` tinha
`_SECRET_PATTERNS` + `redact` (usado antes de enviar ao provedor externo), a trilha de
auditoria (§18.3) tinha um `_redact` local mais fraco (só `chave=valor` + e-mail), e o
relatório tem seu próprio mascaramento parcial. Políticas duplicadas divergem: uma
superfície redige o que a outra vaza. O §11.2 exige um **único ponto reusável**.

## Decisão

Consolidar a redaction em `eigan.ai.sanitize.redact` como **fonte única**:

- Cobre chave privada PEM, AWS access key, JWT, pares `chave=valor` de
  segredo/credencial e e-mail (PII). Idempotente e total (nunca levanta).
- `ai/provider.py` **reexporta** `redact` de `sanitize` (mantém
  `from eigan.ai.provider import redact` funcionando, sem duplicar patterns).
- A trilha de auditoria (`policy/audit.py`) passa a **delegar** a esse ponto — ganhando
  de graça a cobertura mais forte (PEM/JWT/AWS além de `chave=valor`/e-mail).
- Um teste trava a invariante: `provider.redact is sanitize.redact` e
  `audit._redact is sanitize.redact` — não existem duas políticas.

`ai/sanitize.py` importa apenas `re` (sem dependência pesada), então delegar a ele a
partir de `policy`/`report` é uma dependência de utilitário puro, não acoplamento de
domínio a adaptador.

## Consequências

- **Positivas:** uma única política de redaction; a trilha fica mais forte; impossível
  divergência entre superfícies; base para estender a repouso/logs/traces/exports/cache
  (os alvos restantes do §11.2) sempre pelo mesmo ponto.
- **Custos/limites:** o mascaramento *parcial* do relatório (`report/corporate.mask_sensitive`,
  que mostra `AKIA••••MNOP` para triagem) permanece separado por ter finalidade distinta
  (exibir parcialmente vs. remover por completo) — não é duplicação da política de
  remoção, e fica anotado para revisão futura. A extensão a logs/traces/exports/cache é
  incremento seguinte, agora trivial por haver ponto único.
- **Originalidade (P7):** consolidação do próprio código; nada de terceiro copiado.
