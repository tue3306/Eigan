# ADR-0040 — Construção do Knowledge Graph a partir dos findings

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** Parte 2 — Knowledge Graph

## Contexto

O núcleo do Knowledge Graph (ADR-0039) fornece o modelo e a álgebra, mas um grafo vazio
não tem valor. É preciso **populá-lo a partir do que o scan realmente descobriu** — os
findings — para que o Correlation Engine e a IA passem a navegar relações em vez de olhar
findings isolados.

## Decisão

Adicionar `eigan.graph.builder.build_graph(findings, graph=None)`:

- Cada ativo (host extraído de `affected_asset`) vira um nó `HOST`; cada finding vira um
  nó `FINDING` (com severidade/status/ferramenta como atributos).
- Arestas: ativo **AFFECTED_BY** finding; finding **REFERENCES** CWE/OWASP/MITRE quando
  esses campos existem. A **evidência** de cada aresta é a ferramenta de origem.
- **Só cria o que a evidência sustenta** (P1): sem CWE/OWASP/MITRE no finding, nenhum nó
  de referência é inventado.
- **Idempotente e acumulativo**: reexecutar sobre um grafo existente atualiza o
  conhecimento (memória viva), reusando a idempotência do núcleo (ADR-0039) — o mesmo
  finding não duplica nós; um finding novo acumula.

## Consequências

- **Positivas:** o grafo passa a refletir o scan real; base direta para cadeias de ataque
  (Correlation Engine), consultas ("quais ativos afetados por CWE-89?") e histórico (diff
  entre grafos de scans sucessivos). Sem tocar o pipeline existente.
- **Custos/limites:** o builder cobre asset/finding/CWE/OWASP/MITRE — tecnologia, portas,
  credenciais e nuvem entram quando houver evidência estruturada correspondente
  (incremento seguinte, guiado por evidência). A ligação ao fluxo de scan (persistir o
  grafo do engajamento) é próximo passo.
- **Originalidade (P7):** mapeamento próprio findings→grafo; nada de terceiro copiado.
