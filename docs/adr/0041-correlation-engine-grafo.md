# ADR-0041 — Correlation Engine sobre o Knowledge Graph (cadeias + confiança + risco)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** Parte 1 — Correlation Engine (Prioridade Máxima)

## Contexto

O EIGAN tratava a maioria dos findings de forma isolada. `engine.correlation.correlate_assets`
agrupa por ativo e monta uma cadeia linear simples, mas sem **confidence score**, sem
**risco contextual** e sem consumir um modelo de grafo. Com o Knowledge Graph
(ADR-0039/0040) disponível, dá para correlacionar as exposições de um ativo numa cadeia
priorizada e explicável.

## Decisão

Adicionar `eigan.graph.correlation`:

- **`AttackChain`** por ativo, com `steps` (exposições ordenadas da menor para a maior
  severidade), `confidence` (0-100), `risk_score` (0-100) e `narrative` determinística.
- **`compute_confidence(distinct_tools, total_evidence)`** — fórmula **explícita e
  transparente** (P2): cresce com a diversidade de ferramentas (confirmação por fontes
  independentes) e com a corroboração; nunca passa de 100. Nada oculto.
- **Risco contextual** — severidade máxima **modulada pela confiança** e pela largura
  (nº de exposições correlacionadas): não é CVSS cru. Um crítico de fonte única pontua
  alto, mas menos que um crítico corroborado — honesto.
- **Referências** (CWE/OWASP/MITRE) de cada passo vêm do grafo (arestas `REFERENCES`),
  não de invenção (P1).

É complementar a `correlate_assets` (preservado — sem regressão): aqui a fonte de verdade
é o grafo e a saída é a cadeia priorizada com métricas.

## Consequências

- **Positivas:** findings deixam de ser isolados; cada cadeia tem confiança e risco
  explicáveis e referências rastreáveis; ordenação por risco prioriza o que importa; base
  para a narrativa rica via IA (modo online) e para o dashboard.
- **Custos/limites (honestos):** a cadeia é **por ativo** — o encadeamento **cross-asset**
  (recon→…→domain admin) exige arestas de topologia (`CONNECTED_TO`/`COMMUNICATES_WITH`)
  que o builder atual ainda não cria; entra quando houver essa evidência. A narrativa é
  determinística; a versão rica por IA é incremento seguinte (modo online).
- **Originalidade (P7):** algoritmo de confiança/risco e estrutura de cadeia próprios,
  pelos primeiros princípios; nada de terceiro copiado.
