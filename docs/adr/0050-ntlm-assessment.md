# ADR-0050 — NTLM Security Assessment (TIER X.7)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.7

## Contexto

NTLM relay é um vetor de comprometimento comum: SMB/LDAP signing não exigido, LDAP sem
channel binding e NTLMv1 permitido expõem o domínio a retransmissão de autenticação
coagida. A auditoria (X.1) não encontrou essa avaliação.

## Decisão

Adicionar `eigan.analysis.ad.ntlm`, implementação **própria** (P7):

- `NtlmHostConfig` — configuração coletada relevante (SMB/LDAP signing, channel binding,
  NTLMv1, se é DC).
- `assess_ntlm(hosts)` — sinaliza `smb_signing_not_required`,
  `ldap_signing_not_required`, `ldap_no_channel_binding` (estes **críticos em DC**) e
  `ntlmv1_allowed` (crítico), ordenados por severidade.

Decide só a partir do coletado (P1). Indicativo, para avaliação autorizada (P3).

## Consequências

- **Positivas:** cobre X.7; produz os sinais (`smb_signing_not_required`) que, com
  `ntlm_relay`, formam o cenário NTLM Relay de X.11 (ADR-0048); base para correlacionar
  coerção (PetitPotam-like) com relay em incremento seguinte.
- **Custos/limites (honestos):** o *coletor* que popula `NtlmHostConfig` a partir de
  hosts reais é incremento seguinte; a coerção ativa de autenticação é validação gated,
  fora daqui.
- **Originalidade (P7):** modelos e checagens próprios; nada de terceiro copiado.
