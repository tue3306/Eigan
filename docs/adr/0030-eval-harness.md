# ADR-0030 — Harness de avaliação de decisão do agente (evals/)

- **Status:** aceito
- **Data:** 2026-07-31
- **Relacionado:** §3.1 do roadmap; ADR-0007 (núcleo cognitivo/Planner), ADR-0016
  (defesa anti prompt-injection), §2.7 (versionamento de prompt por hash)

## Contexto

O EIGAN tinha ~500 testes de **plumbing**, mas **zero** avaliação da **decisão** do
Planner. Num produto AI-native, a qualidade do produto *é* a qualidade das decisões:
se alguém edita `_AGENTIC_SYSTEM` ou uma regra de cascata e degrada o plano, nada no
CI detecta. Falta uma rede que meça a decisão (quais capacidades, em que ordem, o que
a cascata/IA acrescenta) e falhe em regressão.

## Decisão

Criar `evals/` — um harness de avaliação de decisão, **offline e hermético**:

- **Golden set versionado** (`scenarios/*.yaml`), validado por Pydantic (`schema.py`):
  objetivo, findings injetados (exercitam cascata/replan) e `expected`
  (`must_include`/`must_exclude`/`must_precede`) + `rationale` (documentação viva).
- **Métricas de decisão** (`metrics.py`): recall de capacidade, violações de exclusão,
  ordenação. Puras e determinísticas.
- **Runner** (`runner.py`): roda qualquer `Planner` sobre um cenário (plano inicial +
  replan pelas findings injetadas) e devolve as capacidades produzidas.
- **CI bloqueante** (`pytest evals/` no `ci.yml`): avalia o **substrato determinístico**
  (fonte de verdade da cascata) e o **grounding** do `AgenticPlanner` com
  `CompletionPort` stub — sem chave, sem rede (mantém o CI hermético, §0.4).
- **Cenário adversarial obrigatório:** injeção de prompt no título + IA manipulada
  (stub) tentando ids inventados → grounding descarta e a cascata só casa por
  porta/serviço; o plano nunca contém a capacidade injetada. A defesa da ADR-0016 vira
  garantia testada.
- **Modo online (opt-in, fora do CI):** o mesmo golden set contra um provedor real mede
  qualidade **e custo/latência** por cenário (reusa `observability/`) — números reais,
  nunca fabricados (P1).

## Consequências

- **Positivas:** regressão de decisão vira falha de CI; a defesa anti-injection e a
  cascata determinística ganham cobertura de *decisão*; cada skill/trigger novo (TIER 4)
  passa a exigir um cenário que comprove melhora mensurável.
- **Custos/limites:** a comparação quantitativa determinístico × IA real depende de
  provedor e fica no modo online (custo/rede) — o CI verifica o substrato e o grounding.
  `evals/` não é código de produto (não entra no `mypy src` nem no bandit de produto),
  mas passa por `ruff` e por `pytest evals/`.

## Como validar

```bash
pytest evals/                       # 6 testes: 4 cenários + existência + grounding adversarial
ruff check evals && ruff format --check evals
```
