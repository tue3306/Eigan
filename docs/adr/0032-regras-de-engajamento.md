# ADR-0032 — Regras de Engajamento (RoE) como artefato de 1ª classe

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §18.1

## Contexto

O gate de escopo (`security/scope.py`) e o consent gate dizem *contra o quê* se pode
agir — a base legal (P3). Faltava a camada **operacional** que um engajamento
profissional exige e que um cliente corporativo pede em contrato: *como, quando e até
que ponto* se pode agir. Sem isso, um scan autorizado poderia, dentro do escopo, tocar
produção em horário de pico, atingir um host que o cliente pediu para excluir, ou
escalar para uma classe de teste (exploração) que não foi autorizada.

## Decisão

Introduzir `eigan.policy.roe` com `RulesOfEngagement` declarativo por engajamento,
carregável de YAML. O RoE declara, além do escopo:

- **janelas de tempo permitidas** (`TimeWindow`, com suporte a janelas que atravessam
  a meia-noite) — blackout fora do horário acordado;
- **exclusões** de hosts (reusa o casamento host/CIDR/wildcard do `Scope._matches`),
  portas e paths — proibidos mesmo dentro do escopo;
- **classe de teste máxima autorizada** — reusa `ImpactClass.rank` (recon sim,
  exploração não);
- **teto de taxa por alvo** (`RateLimit`), que expõe o intervalo mínimo derivado
  (enforcement pleno no paralelismo é o §23.1);
- **contatos de emergência**.

`evaluate(action)` devolve uma decisão estruturada (permitido/bloqueado + motivo);
`check(action)` levanta `RoEViolation`. Como o produto exige que "violação de RoE seja
bloqueada como violação de escopo", `RoEViolation` **é subclasse de** `ScopeViolation`
— todo handler que já barra violação de escopo passa a barrar violação de RoE, sem
mudança de call-site (defesa em profundidade). `digest()` dá um SHA-256 canônico do
RoE, referenciável pela trilha de auditoria (§18.3) e pela autorização assinável
(§18.4).

É domínio puro (sem I/O de rede), trivialmente testável. A dependência
`policy → security.scope` já é estabelecida (`policy/engine.py`).

## Consequências

- **Positivas:** engajamento profissional ganha fronteiras operacionais declarativas e
  auditáveis; reuso máximo (P6) de `ImpactClass`, `extract_host`, `Scope._matches`;
  determinismo (`digest`) liga o RoE à trilha e à autorização; violação capturável pela
  mesma malha do escopo.
- **Custos/limites:** o RoE é o primitivo de decisão; o *wiring* que faz o engine
  chamar `roe.check()` em toda ação ativa é um incremento seguinte (junto ao kill
  switch §18.2 e à autorização §18.4). A checagem de janela usa o dia da semana do
  instante de início; janelas overnight que precisam mudar o dia-alvo são um caso raro
  documentado, não tratado aqui.
- **Originalidade (P7):** modelo e algoritmo próprios, pelos primeiros princípios;
  nenhum código/estrutura de terceiro copiado.
