# ADR-0025 — Observabilidade de tokens e custo (telemetria real, custo verificável)

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** observabilidade desde o dia 1 e governança de custo/tokens no
  dashboard (roadmap de plataforma); CLAUDE.md §2/§3.1/§5 (veracidade, anti-invenção);
  ADR-0010 (provedores de IA)
- **Inspiração conceitual:** a disciplina de "observabilidade nasce com o módulo"
  é princípio do EIGAN; implementação 100% original.

## Contexto

O EIGAN é AI-native — toda execução gasta tokens e, portanto, dinheiro. Até aqui
**não havia** medição de uso/custo (confirmado no reconhecimento da Fase 0: nenhum
módulo de `token_usage|cost|tracing`). Sem isso não há governança de custo, que é
requisito de §22. Ao mesmo tempo, **preço de LLM é dado factual e volátil** (varia
por provedor/modelo/contrato/região): embutir uma tabela de preços violaria a regra
de veracidade (§2) e anti-invenção (§3.1/§5).

## Decisão

Novo pacote `src/eigan/observability/`, best-effort (nunca derruba um scan):

- **`usage.py`** — telemetria **real**. `extract_usage()` normaliza os quatro
  formatos oficiais de uso reportados pelos provedores (OpenAI/Azure
  `usage.prompt_tokens|completion_tokens`; Anthropic `usage.input_tokens|output_tokens`;
  Gemini `usageMetadata.promptTokenCount|candidatesTokenCount`; Ollama
  `prompt_eval_count|eval_count`) → `TokenUsage`. `UsageMeter` acumula de forma
  thread-safe; `use_meter()` (contextvar) escopa um medidor por execução, com um
  medidor global como padrão. A gravação é feita no **único choke-point HTTP**
  (`_HTTPProvider._post`), então cobre todos os provedores sem tocar cada `_complete`.
- **`cost.py`** — `CostModel` converte tokens→custo **apenas** com preços que o
  operador confirmou na fonte oficial e marcou `verified: true` em
  `config/ai_pricing.yaml`. Sem entrada verificada, o custo é `None` (**UNVERIFIED**):
  o EIGAN reporta os tokens reais e diz que não sabe o preço — **jamais estima**.
  O arquivo versionado vai com `models: {}` (zero preço fabricado).

## Consequências

- **Positivas:** contagem de tokens real por provedor/modelo, agregável por execução
  (base para o painel de custo do dashboard, §19); custo que respeita a veracidade
  (só aparece quando há preço verificado). Um único ponto de instrumentação.
- **Custos/limites:** o custo em dinheiro fica `UNVERIFIED` até o operador preencher
  `ai_pricing.yaml` — decisão consciente (honestidade > número bonito).
- **Agregação por scan (entregue):** o `CognitiveEngine` escopa um `UsageMeter`
  fresco por `run()` (via uma completion metrificada — `_MeteredCompletion` — que
  roda cada `complete()` sob `use_meter`, sem tocar o loop cognitivo). O
  `CognitiveReport` carrega `token_usage`/`ai_calls`/`token_usage_by_model`; o
  finalize persiste em `scans.token_usage` (JSON) e emite o evento `token_usage`;
  a API expõe em `GET /scans/{id}`. Cobre o **loop cognitivo** (planejamento +
  replan). As narrativas pós-scan (análise/remediação) são chamadas de IA
  separadas cuja agregação por scan fica como próxima unidade.
- **Testes:** `tests/test_observability.py` cobre os 4 formatos, agregação
  thread-safe, escopo por contextvar, gravação via um provedor real (MockTransport)
  e a regra UNVERIFIED do custo.
