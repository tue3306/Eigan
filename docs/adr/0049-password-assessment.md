# ADR-0049 — Password Security Assessment de AD (TIER X.4)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.4

## Contexto

A superfície de comprometimento por senha (ausência de bloqueio → password spraying,
política fraca, contas privilegiadas sem MFA, contas inativas/órfãs, senhas que nunca
expiram) é um dos vetores mais explorados em AD. A auditoria (X.1) não encontrou essa
avaliação.

## Decisão

Adicionar `eigan.analysis.ad.password`, implementação **própria** (P7):

- `PasswordPolicy` e `PwAccount` — atributos coletados da política do domínio e das
  contas.
- `assess_passwords(policy, accounts)` — sinaliza `no_account_lockout` (habilita
  spraying), `weak_min_length`, `no_complexity`, `password_never_expires_policy`,
  `privileged_without_mfa`, `inactive_account`, `privileged_password_never_expires` e
  `orphaned_account`, ordenados por severidade. Os limiares (comprimento < 8, inatividade
  > 90 dias) são **heurísticas declaradas**, não benchmark.

Decide só a partir do que foi coletado (P1); conta desabilitada não gera nada. O módulo
**não** executa spraying — apenas mede a superfície; spraying autorizado com limites para
não travar contas é validação ativa gated, fora daqui (P3).

## Consequências

- **Positivas:** cobre X.4; produz os sinais (`no_account_lockout`/`weak_*` →
  "weak_password_policy"; `privileged_without_mfa` → "mfa_absent") que alimentam os
  cenários de X.11 (ADR-0048); determinístico e explicável.
- **Custos/limites (honestos):** o *coletor* que popula `PasswordPolicy`/`PwAccount` a
  partir de AD real é incremento seguinte; os limiares são declarados e ajustáveis.
- **Originalidade (P7):** modelos e checagens próprios; nada de terceiro copiado.
