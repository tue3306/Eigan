# ADR-0047 — Kerberos Security Assessment (TIER X.3)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.3

## Contexto

Kerberos é um vetor central de comprometimento em AD: contas de serviço com SPN
(kerberoasting), contas sem pré-autenticação (AS-REP roasting) e delegações mal
configuradas (unconstrained/constrained/RBCD). A auditoria (X.1) não encontrou essa
análise.

## Decisão

Adicionar `eigan.analysis.ad.kerberos`, implementação **própria** (P7):

- `AdAccount` — atributos coletados relevantes (SPNs, `DONT_REQ_PREAUTH`, flags de
  delegação, se é DC, se é privilegiada).
- `assess_kerberos(accounts)` — sinaliza `kerberoasting` (usuário habilitado com SPN;
  **crítico** se privilegiado), `asrep_roasting`, `unconstrained_delegation` (apenas fora
  de DC — DCs têm legitimamente), `constrained_delegation` e `rbcd`. Ordenado por
  severidade.

Decide **apenas** a partir de atributos coletados (P1); conta desabilitada não é alvo.
Análise indicativa para avaliação autorizada (P3) — sinaliza, não executa ataque.

## Consequências

- **Positivas:** cobertura das exposições Kerberos clássicas de forma determinística e
  explicável; alimenta a correlação inteligente (X.11: kerberoasting + conta privilegiada
  + política de senha fraca → cenário único) e os relatórios.
- **Custos/limites (honestos):** o *coletor* que popula `AdAccount` a partir de LDAP/AD
  real (com credenciais autorizadas) é incremento seguinte, validado em lab autorizado —
  não fabricado. Não executa o roast em si (isso é validação ativa gated, X/5.1).
- **Originalidade (P7):** modelos e checagens próprios; nada de terceiro copiado — só os
  conceitos padrão da indústria.
