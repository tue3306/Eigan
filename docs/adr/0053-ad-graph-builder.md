# ADR-0053 — Construção do grafo de AD a partir da coleta (TIER X.2/X.10)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.2 / X.10

## Contexto

O analisador de attack paths de AD (ADR-0045) opera sobre o Knowledge Graph, mas faltava
a cola que transforma a **coleta** de AD (objetos e relações) no grafo. Sem ela, o
analisador só rodava sobre grafos montados à mão.

## Decisão

Adicionar `eigan.analysis.ad.graphbuild`:

- `AdCollection` — dados coletados (usuários, grupos, computadores, memberships, controle
  sobre objeto com direito, admin local), com ids já qualificados por tipo.
- `build_ad_graph(collection, graph=None)` — cria os nós `USER`/`GROUP`/`COMPUTER` e as
  arestas `MEMBER_OF`/`HAS_CONTROL`(right)/`ADMIN_TO`, com evidência `ad-collection`.
  Idempotente e acumulativo (reusa o núcleo do grafo); uma aresta para nó não declarado é
  recusada (`KeyError`) — nada de relação para nó fantasma.

Assim `find_attack_paths` roda de ponta a ponta sobre o grafo construído da coleta, no
mesmo substrato do resto da plataforma (P6). Só cria o que a coleta contém (P1).

## Consequências

- **Positivas:** os caminhos de escalonamento passam a ser computados sobre o grafo real
  da coleta; unifica a análise de AD com o Knowledge Graph (consultas, diff histórico,
  correlação com findings de outras origens).
- **Custos/limites (honestos):** o *coletor* que produz `AdCollection` a partir de LDAP/AD
  real (com credenciais autorizadas) é incremento seguinte, validado em lab autorizado —
  não fabricado.
- **Originalidade (P7):** mapeamento próprio coleta→grafo; nada de terceiro copiado.
