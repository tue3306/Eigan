# ADR-0027 — Camada de Validação: confiança explícita e grounded

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** prova de vulnerabilidade / anti-falso-positivo (roadmap de plataforma),
  §8 (camada de *Validation* separada); CLAUDE.md §2/§3.1 (veracidade, anti-invenção),
  §11 (schema de finding com `confidence`/`status`); ADR-0002 (risk)

## Contexto

O §16 exige que **toda finding** tenha um **nível de confiança explícito** e que
findings não validadas sejam **marcadas como tais** — nunca empurrar falso-positivo
como fato. O schema `Finding` já tinha o campo `confidence` (CONFIRMED/FIRM/TENTATIVE/
UNVERIFIED), mas ele era definido isoladamente por cada parser, sem uma etapa de
**validação** que o ajustasse com base em sinais objetivos do conjunto.

## Decisão

`analysis/validation.py` `Validator` — a etapa de *Validation* do §8, rodada no
`_finalize` do `CognitiveEngine` **após o dedup** (que popula `correlated_sources`)
e **antes do risco**. Regra de ouro (§2/§16): a confiança só **sobe** com sinal
real, **nunca** é fabricada e **nunca rebaixa** o que a ferramenta afirmou:

- **Validação ativa** — a vuln foi provada por PoC não-destrutiva (`sqlmap`→SQLi,
  `dalfox`→XSS; nomes verificados nos runners) → `CONFIRMED`, `validated=True`.
- **Corroboração** — ≥ 2 fontes independentes relataram a mesma vuln (mesmo
  `fingerprint`) → ao menos `FIRM`, `validated=True`.
- **Fonte única, sem prova** → preserva a confiança reportada, `validated=False`.

`apply()` atribui a confiança validada a cada finding e devolve um `ValidationSummary`
(total / validadas / distribuição por confiança), emitido no evento
`analysis_complete`. `summarize()` (somente-leitura) alimenta `GET /api/v1/scans/{id}`.

## Consequências

- **Positivas:** confiança passa a refletir **corroboração/prova reais**, não só a
  opinião de uma ferramenta; o consumidor vê o que foi validado vs. tentativo (§16).
  Sem duplicar o engine (é uma função pura sobre findings) — anti over-engineering.
- **Limites (honestos):** hoje "validação ativa" reconhece o subconjunto de tools
  que realmente provam (sqlmap/dalfox); ampliar (ex.: PoC de outras capacidades) é
  incremental. A validação **não** re-executa a ferramenta — usa os sinais já
  coletados (evidência, fontes). Não rebaixa: se um dia uma tool marcar CONFIRMED
  indevidamente, o ajuste é na tool, não aqui.
- **Testes:** `tests/test_validation.py` cobre PoC ativa, corroboração, não-rebaixe,
  fonte única e o resumo (mutável vs. somente-leitura).
