# ADR-0056 — Persistência do Knowledge Graph ("o grafo é permanente")

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** Parte 2 — Knowledge Graph (persistência)

## Contexto

O Knowledge Graph é um **modelo vivo**: cada execução deve **atualizar** o conhecimento
existente, não recomeçar do zero. O núcleo (ADR-0039) já serializa (`to_dict`/`from_dict`)
mas faltava gravar/ler em disco de forma segura para sustentar a memória entre scans.

## Decisão

Adicionar `eigan.graph.persistence`:

- `save_graph(graph, path)` — grava JSON determinístico (`sort_keys`) de forma **atômica**
  (arquivo temporário + `replace`), nunca deixando um grafo meio-escrito.
- `load_graph(path)` — lê o grafo; caminho inexistente ⇒ grafo vazio (primeira execução);
  aceita `clock` para as inserções pós-carga.

Fluxo de acúmulo: `g = load_graph(path); build_graph(findings, graph=g); save_graph(g,
path)` — o conhecimento evolui entre scans, e o histórico sai do `KnowledgeGraph.diff`.

## Consequências

- **Positivas:** o grafo persiste e acumula entre execuções (memória viva da superfície de
  ataque); gravação atômica evita corrupção; base para o histórico e o Impact Analysis
  cross-scan.
- **Custos/limites:** persistência em arquivo JSON (adequada agora); backend SQLite/Postgres
  para escala e consulta indexada é incremento seguinte (liga ao §8.2/§23.3). A ligação ao
  fluxo de scan (salvar o grafo do engajamento automaticamente) é próximo passo.
- **Originalidade (P7):** implementação própria com stdlib; nada de terceiro copiado.
