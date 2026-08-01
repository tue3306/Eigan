# ADR-0060 — Classificação da informação por engajamento (§10.4)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §10.4

## Contexto

Empresas classificam informação (Público/Interno/Confidencial/Restrito) e essa
classificação precisa reger relatório, export e — crucialmente para o EIGAN — o que pode
sair do perímetro. Faltava um campo de primeira classe com essa semântica.

## Decisão

Adicionar `eigan.policy.classification`:

- `Classification` — enum ordenado (`rank`), com `label` em pt-BR e `at_least`.
- `most_restrictive(levels)` — a classificação do **engajamento** é a mais restritiva dos
  seus findings.
- `banner(level)` — faixa para cabeçalho/rodapé de relatório.
- `requires_redaction(level)` — a partir de `CONFIDENCIAL`, exports/telemetria exigem
  redaction (P8).
- `permits_external_provider(level)` — `RESTRITO` **não** pode ir a provedor de IA externo:
  só caminho soberano/local, reforçando P8/soberania de dados.

## Consequências

- **Positivas:** classificação propagável a relatório/export/acesso; amarra decisões de
  redaction e de roteamento de IA à sensibilidade — o `RESTRITO` fica preso ao perímetro
  por construção (moat de soberania).
- **Custos/limites:** a fiação nos pontos que exportam/roteiam IA (aplicar
  `permits_external_provider` na seleção de provedor; `requires_redaction` nos exports) é
  incremento seguinte; a primitiva e suas regras já estão aqui e testadas.
- **Originalidade (P7):** modelo próprio; nada de terceiro copiado.
