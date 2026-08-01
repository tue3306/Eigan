# ADR-0051 — Shadow Credentials Assessment (TIER X.8)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.8

## Contexto

Shadow Credentials é uma técnica de aquisição/persistência: quem pode escrever
`msDS-KeyCredentialLink` de um objeto de AD adiciona uma credencial baseada em
certificado e autentica como o objeto. A auditoria (X.1) não encontrou essa análise.

## Decisão

Adicionar `eigan.analysis.ad.shadowcreds`, implementação **própria** (P7):

- `AdObjectKeyCred` — estado coletado do `msDS-KeyCredentialLink` de um objeto (gravável
  por baixo privilégio, já presente, alvo privilegiado).
- `assess_shadow_credentials(objects)` — sinaliza `shadow_credentials_writable`
  (**crítico** em objeto privilegiado; alto caso contrário) e `shadow_credentials_present`
  (médio, para revisão de persistência), ordenados por severidade.

Decide só a partir do coletado (P1). Indicativo, para avaliação autorizada (P3).

## Consequências

- **Positivas:** cobre X.8; produz os sinais (`shadow_credentials` + `acl_misconfig`) que
  formam o cenário de persistência de X.11 (ADR-0048), no mesmo alvo; determinístico.
- **Custos/limites (honestos):** o *coletor* de ACL/atributos reais é incremento
  seguinte; a adição efetiva de shadow credential é ação ativa gated, fora daqui.
- **Originalidade (P7):** modelos e checagens próprios; nada de terceiro copiado.
