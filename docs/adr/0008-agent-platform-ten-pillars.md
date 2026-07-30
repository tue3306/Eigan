# ADR-0008 — Arquitetura de agentes e os 10 pilares da plataforma autônoma

- **Status:** aceito
- **Data:** 2026-07-10
- **Relaciona-se com:** [ADR-0007](0007-cognitive-core-planner.md) (núcleo
  cognitivo: Planner/Capabilities/Agents), [ADR-0004](0004-cascade-orchestration-and-web-ui.md)
  (cascata determinística), [ADR-0002](0002-risk-engine-feeds.md) (risco/feeds)
- **Superado em parte por:** [ADR-0012](0012-ai-native-mandatory.md) — a IA passou a
  ser **obrigatória** (AI-native). Onde este ADR diz "sem chave, o produto funciona
  inteiro", leia: o substrato determinístico (cascata, ToolSelector, Policy Engine)
  **existe e é o piso de segurança que a IA comanda**, mas **não há "modo sem IA" que
  produza um scan** — sem provedor, o EIGAN recusa (P5).

## Contexto

A visão de produto é sair de "mais um scanner" para uma **plataforma autônoma**
orientada por objetivos, expressa em **10 pilares**. O risco é virar *stub que
finge funcionar*. Este ADR fixa **os contratos** entre as peças para que os 10
pilares **pluguem no mesmo núcleo** (ADR-0007) sem reescrevê-lo — a meta de "100+
módulos sem tocar no Core" — e declara, honestamente, **o que é real e o que é
scaffold** nesta fase.

Restrições inegociáveis (CLAUDE.md) que valem para todos os pilares:

- **A IA planeja/prioriza/interpreta; o engine determinístico executa e detecta**
  (§3.3). Fronteira explícita no código e nos logs.
- **Todo recurso de IA tem fallback determinístico** (§3.4). *(Superado por
  [ADR-0012](0012-ai-native-mandatory.md): o fallback é resiliência intra-scan do
  substrato que a IA comanda, **não** um "modo sem IA" — sem provedor não há scan.)*
- **Autorização/escopo são pré-condição de toda ação ativa** (§2); consent gate
  nunca contornado por agente/planner.
- **Anti-invenção** (§3.1): enriquecimento externo só de fonte oficial, ou
  `UNVERIFIED`. Nada de artefato aplicado automaticamente em terceiros.

## Decisão — contratos entre as peças

O núcleo cognitivo (ADR-0007) já define `Goal → Planner → [Agent → ToolSelector →
Execution] → Feedback → replan → Stop`. Os pilares consomem essas portas e
adicionam mais três contratos, todos **domínio puro + porta de infra**:

| Contrato | Módulo | Entrada → Saída | Fronteira |
|---|---|---|---|
| **Memória / Diff** | `analysis/diff.py` + `FindingStore.find_previous_scan` | (scan anterior, scan atual) → `ScanDiff` (novos/corrigidos/persistentes + novos ativos/serviços) | **Determinístico**; a IA só *narra* o diff (opcional, com fallback). |
| **Correlação** | `engine/correlation.py` (+ `findings/dedup.py`) | findings de N fontes → findings correlacionados por ativo | Determinístico; enriquecimento externo só verificável/marcado. |
| **Remediação** | `report/remediation.py` | `Finding` → `RemediationArtifact` (playbook revisável) | Determinístico por template; **nunca auto-aplicado**; formatos não construídos são scaffold honesto. |

As peças se comunicam **por dados** (dataclasses do domínio), não por chamadas
diretas entre pilares — o que mantém cada um testável isolado e plugável.

## Status dos 10 pilares (real × scaffold — honesto)

| # | Pilar | Status | Onde |
|---|---|---|---|
| 1 | **Agentes de IA (Planner)** | **REAL (fundação)** — AIPlanner + agentes; Recon real, demais scaffold | `engine/cognitive/` (ADR-0007) |
| 2 | **Memória entre scans (diff)** | **REAL** — diff determinístico; IA narra (opcional) | `analysis/diff.py`, CLI `eigan diff` |
| 3 | **Correlation Engine** | **REAL (base)** — correlação por ativo + dedup por fingerprint | `engine/correlation.py`, `findings/dedup.py` |
| 4 | **Attack Planner** | **REAL** — política do Planner, decisão logada/justificada; ativo destrutivo exige opt-in | `engine/cognitive/planner.py` |
| 5 | **Auto Explainer** | **REAL (base)** — Enricher com fallback determinístico + IA opcional | `ai/provider.py` (`Enricher`) |
| 6 | **Auto Remediation (Blue)** | **REAL (1 formato: Ansible)** — sugestão revisável; demais formatos scaffold | `report/remediation.py`, CLI `eigan remediate` |
| 7 | **Purple Team (loop Red↔Blue)** | **SCAFFOLD** — plugins `attack-simulation`/`control-validation`/`detection-validation` declarados | `plugins/purple/*` |
| 8 | **Dashboard executivo** | **REAL (base)** — relatório executivo (risco agregado, sem CVE cru) | `report/deterministic.py` (estilo executivo) |
| 9 | **AI Workflow ponta a ponta** | **REAL (fundação)** — orquestrado pelo `CognitiveEngine`, gate por fase ativa | `engine/cognitive/engine.py` |
| 10 | **Marketplace** | **DOC-ONLY** — sem código nesta fase | `docs/roadmap/` |

O que é **scaffold** aparece no `doctor` (agentes `built=false`, plugins roadmap)
como *sugerido, não executado* — nunca finge rodar. Novos pilares/agentes = novo
módulo + registro; **o Core não muda**.

## Alternativas consideradas

- **Entregar os 10 pilares "completos" agora.** Rejeitado: produziria stubs que
  fingem funcionar (viola §3.6). Preferimos *fundação real + camadas de verdade +
  scaffold honesto*, faseando com contratos estáveis.
- **Acoplar pilares por chamadas diretas** (diff chamando remediação chamando
  reporting). Rejeitado: acopla e dificulta teste isolado. Comunicação por dados
  do domínio mantém cada pilar plugável.

## Consequências

- Cada pilar real traz ADR/entrada no roadmap, código com fronteira IA/engine
  explícita, **fallback determinístico** e teste. Cada pilar scaffold é
  registrado honestamente (roadmap + `doctor`).
- Comandos de verificação: `eigan diff --scan <B>` (memória/diff) e
  `eigan remediate --scan <id>` (remediação) — ambos determinísticos, sem
  depender de IA.
