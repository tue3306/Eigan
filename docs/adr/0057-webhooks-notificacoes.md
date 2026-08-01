# ADR-0057 — Notificações/webhooks acima de limiar de severidade (§16.1)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §16.1

## Contexto

Uma plataforma vive no fluxo do time: findings relevantes precisam chegar a canais
externos (webhook/chat). Faltava essa emissão — com as garantias do projeto: redaction no
payload (P8) e nenhum segredo no repositório (P4).

## Decisão

Criar o pacote `eigan.integrations` com `webhooks`:

- `build_finding_payload(finding)` — payload **redigido** (reusa `ai.sanitize.redact`),
  **sem evidência bruta** (que pode conter segredo).
- `WebhookNotifier(sink, min_severity=)` — entrega ao **sink injetável** apenas findings
  que cruzam o limiar; devolve a contagem entregue.

O transporte concreto (HTTP com httpx) é um **adaptador injetável** plugado por fora — o
núcleo (payload + filtro) é puro e testável, e o caminho padrão fica sem dependência de
rede (restrição #7). A URL/token do webhook vêm do ambiente, nunca do repositório (P4).

## Consequências

- **Positivas:** eventos entregáveis a webhooks/canais com redaction e por limiar; reusa a
  redaction unificada (§11.2); testável sem rede (sink falso).
- **Custos/limites:** o adaptador HTTP real e a configuração (env) são incremento
  seguinte; a assinatura/verificação do payload (HMAC) pode ser adicionada quando houver
  necessidade.
- **Originalidade (P7):** implementação própria; nada de terceiro copiado.
