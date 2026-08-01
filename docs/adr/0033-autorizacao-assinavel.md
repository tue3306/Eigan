# ADR-0033 — Autorização assinável por engajamento (HMAC + validade)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §18.4

## Contexto

O consent gate inline afirma "tenho autorização" no momento do scan, mas não produz um
artefato **verificável e com validade** que sustente o engajamento perante auditoria ou
contrato. Um engajamento profissional precisa poder provar, no início de toda ação
ativa, que existe autorização vigente ligada a um documento assinado, a um responsável,
a um escopo e a um RoE (§18.1) específicos — e que essa autorização **expira**.

## Decisão

Introduzir `eigan.policy.authorization.Authorization`: um registro assinado por
HMAC-SHA256 com um segredo do operador (**nunca versionado** — P4).

- O conteúdo assinado inclui `engagement`, `document_ref`, `responsible`,
  `scope_digest`, `roe_digest` (liga ao §18.1) e a validade (`issued_at`/`expires_at`).
- `sign(secret)` devolve uma cópia assinada; o segredo **não** é armazenado no objeto,
  então o registro assinado pode ser persistido com segurança — sem o segredo, ninguém
  o forja.
- `verify(secret, now=...)` checa, nesta ordem: assinatura íntegra por
  `hmac.compare_digest` (comparação em **tempo constante**, coerente com o cuidado do
  §7.3), vigência (`now >= issued_at`) e expiração (`now <= expires_at`, senão
  `AuthorizationExpired`). Adulterar qualquer campo — inclusive esticar `expires_at` —
  invalida a assinatura.

É domínio puro e determinístico. O *wiring* que exige a autorização vigente em cada
ponto de entrada de ação ativa (CLI/API/MCP) é um incremento seguinte, junto ao RoE
(§18.1), ao kill switch (§18.2) e à trilha (§18.3).

## Consequências

- **Positivas:** autorização verificável, com validade e expiração respeitadas; ligada
  ao escopo e ao RoE por digest; comparação em tempo constante; segredo fora do objeto
  e do repositório (P4); serializável sem perder verificabilidade.
- **Custos/limites:** HMAC prova integridade e origem *para quem detém o segredo* —
  não é assinatura assimétrica (não há verificação por terceiro sem o segredo
  compartilhado); se o modelo de ameaça exigir verificação por terceiro, uma variante
  com chave assimétrica é evolução futura. A rotação/custódia do segredo é do operador
  (liga ao §20.3, gestão de segredos).
- **Originalidade (P7):** implementação própria com primitivos stdlib (`hmac`,
  `hashlib`); nenhum código de terceiro copiado.
