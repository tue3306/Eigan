# ADR-0042 — Consultas inteligentes e Impact Analysis sobre o Knowledge Graph

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** Parte 2 — Knowledge Graph (consultas + impact analysis)

## Contexto

Com o grafo populado (ADR-0040) e o Correlation Engine (ADR-0041), falta a camada que
**responde perguntas navegando o grafo** em vez de varrer findings soltos — o que o
master prompt chama de "Consultas Inteligentes" e "Impact Analysis". Essas respostas são
o insumo estruturado que a IA usa para responder em linguagem natural (modo online) e que
o dashboard exibe.

## Decisão

Adicionar `eigan.graph.query` com consultas de alto nível, todas determinísticas e
baseadas apenas no conteúdo do grafo (P1):

- **`assets_affected_by(graph, reference_id)`** — Impact Analysis: dada uma referência
  (ex.: `cwe:CWE-89`), navega referência ← findings ← ativos e devolve os ativos
  afetados. Responde "quando surge uma CVE/CWE, quais ativos são impactados?".
- **`assets_added_since(graph, when)`** — histórico: ativos cujo `first_seen >= when`
  (novos na superfície desde o último scan).
- **`reference_prevalence(graph, kind=CWE)`** — quais referências (CWE/OWASP/MITRE) são
  mais presentes, ordenadas por contagem.
- **`riskiest_assets(graph, top=N)`** — ativos de maior risco como cadeias priorizadas
  (reusa o Correlation Engine).

## Consequências

- **Positivas:** o grafo passa a responder perguntas de negócio ("qual ativo é mais
  arriscado?", "quais ativos afetados por esta CWE?", "o que surgiu desde a semana
  passada?") de forma determinística e verificável; base direta para a resposta em
  linguagem natural da IA e para a visualização.
- **Custos/limites (honestos):** o Impact Analysis opera sobre as referências que o
  builder cria (CWE/OWASP/MITRE); CVE/tecnologia/credencial entram quando o builder as
  materializar como nós (guiado por evidência). A resposta em linguagem natural é o modo
  online.
- **Originalidade (P7):** consultas próprias sobre o modelo do EIGAN; nada de terceiro
  copiado.
