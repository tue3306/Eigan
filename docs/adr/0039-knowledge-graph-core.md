# ADR-0039 — Knowledge Graph: núcleo (nós/arestas tipados, diff, persistência)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** Parte 2 — Knowledge Graph (evolução do Correlation Engine)

## Contexto

O EIGAN correlaciona findings por ativo (`engine/correlation.py::correlate_assets`),
mas trata a maioria das descobertas de forma isolada. O objetivo de longo prazo é uma
plataforma de *Attack Surface Intelligence*: um **modelo vivo** da infraestrutura em que
tudo que é descoberto vira nó e toda relação vira aresta tipada — base sobre a qual o
Correlation Engine constrói cadeias de ataque e a IA responde consultas navegando o
grafo, não olhando findings soltos.

Auditoria (X.1): não existia módulo de grafo; `correlate_assets` é parcial (agrupa por
host + cadeia linear simples) e **é preservado**. Este ADR adiciona o substrato novo sem
duplicar nem alterar o existente.

## Decisão

Criar o pacote `eigan.graph` com o **núcleo** do Knowledge Graph:

- `model.py` — `NodeKind`/`EdgeKind` (tipos do domínio de segurança, conceitos padrão da
  indústria, P7), `Node` (identidade = `node_id`) e `Edge` (identidade =
  `(src, kind, dst)`, com `evidence` — nenhuma relação sem fonte).
- `graph.py::KnowledgeGraph` — **inserção idempotente** (reinserir mescla atributos e
  atualiza `last_seen`; mudar o `kind` de um id é `GraphConflict`; aresta exige nós
  existentes); **consulta** (`nodes_by_kind`, `neighbors` por direção/tipo, `find` por
  atributo); **diff** scan-a-scan (`GraphDiff`: nós/arestas adicionados/removidos) para o
  histórico; **serialização** determinística (`to_dict`/`from_dict`) para persistência.

Tudo é dado puro, sem I/O, determinístico (saída ordenada; relógio de
`first_seen`/`last_seen` injetável — liga ao §21.3).

## Consequências

- **Positivas:** substrato para o Correlation Engine (confidence, cadeias cross-asset),
  para o histórico ("o que mudou desde o último scan") e para consultas navegáveis; não
  toca `correlate_assets` (sem regressão); persistível e diferenciável.
- **Custos/limites:** persistência em SQLite/arquivo, o *builder* que popula o grafo a
  partir dos findings/plugins, a visualização interativa e a integração com a IA são
  incrementos seguintes — este ADR entrega o modelo e a álgebra do grafo. `NodeKind` é um
  subconjunto curado, extensível conforme novas capacidades (P6).
- **Originalidade (P7):** modelo, tipos e algoritmos próprios, pelos primeiros
  princípios; nenhum código/estrutura de terceiro (BloodHound et al.) copiado — apenas os
  conceitos padrão da indústria.
