# ADR-0048 — Correlação inteligente de sinais de AD em cenários (TIER X.11)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.11

## Contexto

Os analisadores de AD (attack path X.2, ESC X.6, Kerberos X.3) produzem sinais atômicos.
Um relatório com N findings soltos esconde a história: o valor está em reconhecer que
**vários sinais juntos** formam um caminho de comprometimento e apresentá-los como **um
cenário único priorizado**, evitando duplicação.

## Decisão

Adicionar `eigan.analysis.ad.scenarios`:

- `AdSignal` — sinal atômico normalizado (kind, alvo, severidade).
- `CombinationRule` — combinação perigosa conhecida (conjunto de kinds exigidos,
  severidade elevada, descrição; `same_target` quando os sinais precisam compartilhar o
  objeto).
- `DEFAULT_RULES` — as combinações do roadmap: Kerberoasting + conta privilegiada +
  política de senha fraca; ESC1 + template vulnerável + permissões excessivas; Shadow
  Credentials + ACL incorreta (mesmo alvo); NTLM Relay + SMB Signing desabilitado;
  Password Spraying + MFA ausente.
- `correlate_scenarios(signals)` — dispara cada regra cujos sinais estão presentes
  (respeitando `same_target`), emitindo **um** `AttackScenario` priorizado com os sinais
  constituintes e uma `confidence` transparente que cresce com o nº de sinais. Ordenado
  por severidade/confiança.

Só dispara com base nos sinais coletados (P1); nunca inventa a combinação.

## Consequências

- **Positivas:** o operador recebe cenários acionáveis ("comprometimento de domínio via
  Kerberoasting") em vez de findings isolados; menos ruído, mais contexto; base para a
  narrativa da IA (X.10) e para o dashboard.
- **Custos/limites (honestos):** os sinais vêm dos analisadores (Kerberos/ESC/attack
  path) e de coletores futuros (senha X.4, NTLM X.7, shadow creds X.8); o *adaptador* que
  converte as saídas desses analisadores em `AdSignal` é incremento seguinte. As regras
  são um conjunto extensível por dados (P6).
- **Originalidade (P7):** modelo de regras e motor de correlação próprios; nada de
  terceiro copiado — só as combinações padrão da indústria.
