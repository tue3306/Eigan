# ADR-0022 — Correlação Purple (ataque × detecção)

- **Status:** aceito (retroativo — decisão já implementada)
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §3.1 (não inventar cobertura), ADR-0021 (Blue Engine)

## Contexto

A razão de existir do Purple é medir **se a defesa vê o ataque**. Faltava
correlacionar as técnicas ATT&CK **atacadas** (findings Red) com as **detectadas**
(findings Blue).

## Decisão

`analysis/purple.py` (determinístico): separa os findings em Red × Blue (por
`source_tool` ∈ ferramentas de detecção — `log-analysis` + plugins da categoria
BLUE), agrupa por **família de técnica** ATT&CK e classifica cada uma:

- **covered** — atacada E detectada (defesa vê);
- **gap** (ponto cego) — atacada SEM detecção (o achado mais valioso);
- **detection_only** — detectada sem ataque correspondente no dataset.

Produz `PurpleReport` (covered/gaps/detection_only + `coverage_pct`). A IA apenas
**narra** os gaps (opcional) — nunca inventa cobertura (§3.1). Exposto via
`eigan purple`, `POST /api/v1/purple` e view no dashboard.

## Consequências

- **Positivas:** pontos cegos explícitos e acionáveis; base para o **Purple loop**
  autônomo (gerar regra Sigma para cada gap — roadmap).
- **Custos:** a correlação é no nível de família de técnica (não sub-técnica exata)
  para evitar falsos gaps por granularidade — decisão conservadora e honesta.
