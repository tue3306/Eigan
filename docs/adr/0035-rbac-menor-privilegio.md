# ADR-0035 — RBAC com menor privilégio (papéis + tokens com escopo)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §20.1

## Contexto

A autenticação da API é por **token único** (ADR-0014): quem o possui tem poder total,
e não há como responder "quem disparou este scan?". Numa equipe de segurança — ou numa
consultoria com vários clientes na mesma instalação — isso é bloqueador de adoção
corporativa e fere o princípio de menor privilégio. É também pré-requisito da atribuição
de identidade (§20.2) e do isolamento por engajamento (§11.4).

## Decisão

Introduzir `eigan.security.rbac`, **aditivo** ao token único (que segue válido como o
papel de fato `admin` local, sem regressão — ADR-0014 preservado):

- **Papéis** (`Role`) com permissões de menor privilégio (`ROLE_PERMISSIONS`):
  - `admin` — todas as permissões;
  - `operator` — dispara/para scans, aprova ações (HITL §19.5), lê e gera relatório;
  - `analyst` — marca finding (§13.1), gera relatório, lê;
  - `auditor` — lê findings e a trilha (§18.3); **não executa nada**.
- **`Principal`** — identidade autenticada com papel, conjunto de engajamentos
  (vazio = todos), e validade (`expires_at`).
- **`authorize(principal, permission, engagement=, now=)`** — nega com `AccessDenied`
  na ordem expiração → permissão do papel → escopo de engajamento.
- **`TokenRegistry`** — vincula tokens a principals guardando **apenas o SHA-256** do
  token (nunca o valor em claro — P4/P8); suporta **expiração** e **revogação**.

É domínio puro (sem I/O de rede), trivialmente testável.

## Consequências

- **Positivas:** menor privilégio por papel; escopo por engajamento; tokens expiráveis
  e revogáveis; token nunca em claro; base para "quem fez o quê" (§20.2). Sem quebrar o
  token único (ADR-0014).
- **Custos/limites:** o *wiring* (a API resolver o token ao `Principal` e chamar
  `authorize` por endpoint; emitir/rotacionar tokens de papel) é um incremento
  seguinte. O lookup por digest não é comparação em tempo constante entre entradas, mas
  o segredo nunca é comparado em claro (sha256 é resistente a pré-imagem) — aceitável e
  padrão. A gestão/custódia dos segredos de token é do operador (§20.3).
- **Originalidade (P7):** modelo de papéis/permissões próprio, pelos primeiros
  princípios; nenhum código de terceiro copiado.
