# GAP_ANALYSIS — EIGAN × capacidades‑alvo (Fase 0)

> **Propósito.** Matriz honesta *EIGAN de hoje* × *plataforma‑alvo* do roadmap
> de plataforma, mais comparações conceituais **EIGAN × Strix** e **EIGAN × Wazuh**.
> Base para priorizar as Fases 1–7. **Regra de veracidade:** o estado "existe" foi
> conferido no código (`b7fdcba`); os fatos sobre Strix/Wazuh vêm dos **READMEs
> oficiais** (fetch em 2026‑07‑14) e estão marcados quando conceituais.
>
> Legenda de estado: ✅ existe · 🟡 parcial · ⛔ ausente · 🗑️ remover/consolidar.
> Esforço: **P** (dias) · **M** (1–2 semanas) · **G** (semanas). Prioridade: 1 (alta)–4 (baixa).

---

## 1. Matriz de capacidades

| # | Capacidade‑alvo | Estado | Onde (evidência) | Prio | Esforço |
|---|---|---|---|---|---|
| 1 | Core: contratos/portas + domínio sem I/O | ✅ | `capability.py`, `perspective.py`, `findings/schema.py`, Protocols em `engine/` | — | — |
| 2 | Plugin system + auto‑discovery (Core intacto) | ✅ | `engine/registry.py`, `plugin.py`; 38 plugins | — | — |
| 3 | Tool Registry + Tool Selector | ✅ | `engine/registry.py`, `cognitive/selection.py` | — | — |
| 4 | Tool Adapters (health/timeout/retry/sandbox/fallback) | 🟡 | runners de plugin existem; **falta contrato uniforme** com health_check/retry/backoff/rate‑limit padronizados | 2 | M |
| 5 | Núcleo multi‑agente (Planner/Coord/Recon/Exec/Validator/Report/Memory) | 🟡 | `cognitive/agent.py`, `engine.py`, `planner.py` — **Coordinator/Memory/Validator formais faltam** | 1 | M |
| 6 | AI Engine em camadas (Planning/Reasoning/Execution/Validation) | 🟡 | Planning/Execution ✅; **Reasoning/Validation como camadas nomeadas** 🟡 | 1 | M |
| 7 | Reflection / Critique / Self‑Critic | ⛔ | não há (`grep reflection` → 0) | 2 | M |
| 8 | Learning entre execuções | ⛔ | replan é intra‑scan; sem aprendizado cross‑run | 3 | G |
| 9 | Memory persistente (working/long‑term/projeto/execução/KB) | ⛔ | `grep memory` → 1 arquivo; sem camada de memória | 2 | M |
| 10 | Multi‑provedor de IA (8+) | ✅ | `ai/provider.py`: anthropic, openai, gemini, openrouter, groq, together, azure, ollama | — | — |
| 11 | Grounding + saída estruturada (Pydantic) | ✅ | `cognitive/planner.py` (JSON validado, ids inventados descartados) | — | — |
| 12 | Defesa anti prompt‑injection + redaction | ✅ | `ai/sanitize.py`, ADR‑0016; redaction antes de provedor externo | — | — |
| 13 | Policy/Guardrail Engine (ImpactClass + HITL) | ✅ | `policy/engine.py`, `impact.py`, ADR‑0011 | — | — |
| 14 | Gate de escopo + consent gate | ✅ | `security/scope.py`, `consent.py` | — | — |
| 15 | SSRF hardening + auth de API | ✅ | `security/ssrf.py` (ADR‑0015), `apitoken.py` (ADR‑0014) | — | — |
| 16 | Event Bus (pub/sub desacoplado) | ⛔ | `engine/events.py` é sink de progresso, não bus | 1 | M |
| 17 | Workflow Engine por grafo (DAG, retomável) | ⛔ | plano é fila linear com replan | 2 | G |
| 18 | Pipeline defensivo de eventos (coleta→…→resposta) | 🟡 | `engine/blue.py`, `analysis/*` (findings); **pipeline de *eventos*** falta | 2 | G |
| 19 | Rule engine moderno (regras+LLM+KG) | 🟡 | plugins de detecção scaffold; sem engine de regras versionadas | 3 | G |
| 20 | Threat Intel enrichment (CVE/CWE/CAPEC/EPSS/KEV/IOC) | 🟡 | `engine/risk.py`, `feeds.py` (EPSS/KEV/CVE) ✅; **CAPEC/IOC/ExploitDB** 🟡 | 2 | M |
| 21 | RAG sobre CVE/CWE | ⛔ | não há índice/consulta semântica | 3 | M |
| 22 | Knowledge Graph (ativo↔serviço↔vuln↔ATT&CK↔controle) | ⛔ | `knowledge/` é *skills*, não grafo | 3 | G |
| 23 | Prova de vuln / PoC + anti‑falso‑positivo (confiança explícita) | 🟡 | `Finding` tem evidence/confidence; **validação ativa/PoC** limitada | 1 | M |
| 24 | Enriquecimento MITRE ATT&CK | ✅ | `analysis/attack.py`, `knowledge/attack/techniques.yaml` | — | — |
| 25 | Compliance (PCI/NIST/CIS/ISO/LGPD/HIPAA) | 🟡 | `analysis/compliance.py`, `knowledge/compliance/mappings.yaml` (subset) | 3 | M |
| 26 | Asset Management + histórico entre scans | 🟡 | `analysis/inventory.py`, `analysis/diff.py`; **inventário 1ª classe** 🟡 | 2 | M |
| 27 | Attack Surface Management (contínuo) | 🟡 | recon real (subfinder/dnsx/httpx/naabu); **ASM contínuo/monitorado** ⛔ | 3 | G |
| 28 | Persistência agnóstica (SQLite/Postgres, Repository) | 🟡 | `findings/store.py` SQLite (Repository); **Postgres** declarado, validar | 2 | M |
| 29 | Observabilidade: tracing + logging estruturado + métricas | 🟡 | `logging_setup.py` + eventos; **tracing/métricas** ⛔ | 1 | M |
| 30 | Observabilidade de **token usage / custo** de execução | ⛔ | `grep token_usage\|cost\|tracing` no `src/` → nenhum módulo | 1 | P |
| 31 | API REST versionada + WebSocket streaming | ✅ | `api/app.py` (`/api/v1` + `/ws/...`) | — | — |
| 32 | Dashboard tempo real (dark) + timeline de raciocínio | 🟡 | SPA em `api/static/`; **painéis MITRE/Attack‑Graph/custo** 🟡 | 2 | M |
| 33 | SDK | ⛔ | não há pacote `sdk` | 4 | M |
| 34 | CLI + TUI | ✅/🟡 | CLI Click ✅; TUI (`cli/tui.py`, extra `[tui]`) 🟡 | 3 | P |
| 35 | Relatórios HTML/PDF/JSON/CSV/SARIF | ✅ | `report/deterministic.py`, `exporters.py` (SARIF), `corporate.py` | — | — |
| 36 | Sandbox real p/ ferramentas e código | 🟡 | `docker/` + plumbing seguro; **sandbox efêmero por execução** 🟡 | 2 | M |
| 37 | EIGAN Agent de endpoint (lifecycle/heartbeat/FIM/inventário/active‑response) | ⛔ | não há agente de endpoint | 4 | G |
| 38 | Cluster / workers distribuídos / HA | ⛔ | monólito single‑node | 4 | G |
| 39 | CI (lint+type+test) + smoke‑install | ✅ | `.github/workflows/ci.yml` | — | — |
| 40 | Docs: CURRENT_STATE / TARGET / GAP + ADRs | ✅ | este pacote (Fase 0) + 24 ADRs | — | — |

### 1.1 Itens a **consolidar/remover** (🗑️ — anti‑duplicação §24)

- **`AIPlanner` legado** vs `AgenticPlanner`: o `AIPlanner` (só reordena) é
  redundante frente ao `AgenticPlanner`. Avaliar deprecar para reduzir superfície.
- **Badge de testes no README** (`234 passed`) desatualizado → **446**. Corrigir e,
  idealmente, **gerar via CI** para nunca mais divergir.
- **`vulnforge` alias** depreciado: manter só enquanto houver usuários; planejar remoção.

---

## 2. EIGAN × Strix (comparação conceitual)

> Fonte: README oficial do Strix (`github.com/usestrix/strix`, fetch 2026‑07‑14).
> Comparação **por características verificáveis**, sem alegação depreciativa (§16).

| Dimensão | EIGAN (hoje) | Strix (conforme README) |
|---|---|---|
| Posicionamento | Agente AI‑native Red/Blue/Purple, Web+Infra, Outside‑In/Inside‑Out | Pentest autônomo AI, developer‑first (código/repos/web apps) |
| Orquestração IA | Planner cognitivo (Determinístico/AI/Agentic), replan por onda | "Graph of Agents"; agentes especializados que colaboram e encadeiam vulns |
| Ferramentas | 38 plugins intercambiáveis por *capability*; Tool Selector | Proxy HTTP (Caido), browser (Playwright), Nuclei, shell, runtime Python |
| Sandbox | `docker/` + plumbing seguro (lista de args) | Sandbox Docker (imagem baixada no 1º run) |
| PoC / validação | Finding com evidence/confidence; validação ativa 🟡 | **PoC executável por vuln**; "valida via prova de conceito real" |
| Providers | 8 via `ProviderSpec` | LiteLLM (OpenAI, Anthropic, Vertex, Bedrock, Azure, Ollama, LMStudio) |
| Guardrails | **Policy Engine + escopo + consent + anti‑injection + redaction** | Escopo por instrução/PR‑diff (foco em CI); guardrails formais não detalhados no README |
| Defensivo (Blue) | Coluna Blue/Purple (parcial) | Foco ofensivo; sem coluna defensiva |
| CI/CD | `ci.yml` + smoke‑install; gate de scan opcional | GitHub Actions com scan por diff de PR |
| Remediação | Narrativa por IA + plano de remediação | "Patches como PRs prontos para merge" |

**O que extrair (o *porquê*, não código):** (a) **grafo de agentes** com
colaboração/encadeamento explícito de vulns; (b) **PoC executável** como padrão
anti‑falso‑positivo; (c) **remediação como PR**. **Diferencial do EIGAN a
preservar:** envelope de **governança/guardrails** (Policy Engine, escopo,
anti‑injection, redaction) e a **coluna defensiva**.

---

## 3. EIGAN × Wazuh (comparação conceitual)

> Fonte: README oficial do Wazuh (`github.com/wazuh/wazuh`, fetch 2026‑07‑14).

| Dimensão | EIGAN (hoje) | Wazuh (conforme README) |
|---|---|---|
| Natureza | Agente ofensivo/assessment dirigido por IA | Plataforma de **detecção e resposta** (threat prevention/detection/response) |
| Arquitetura | Monólito modular single‑node; scanner central | **Agente de endpoint + servidor**; integra Elastic Stack; dashboard |
| Coleta | Ferramentas de scan sob demanda | Agentes em endpoints: logs, inventário, FIM contínuo |
| Pipeline | Findings → dedup → risk → report | **Eventos**: coleta → decoders/regras → correlação → alerta |
| Rule engine | Cascata declarativa + IA (findings) | Rule engine com regex, prioridade/severidade, mapeamento MITRE |
| Vuln detection | Scan ativo + enriquecimento EPSS/KEV/CVE | Correlaciona inventário de software × CVE DB |
| FIM / SCA / Active Response | ⛔ (não há agente de endpoint) | ✅ FIM, config assessment, active response |
| Cloud/Container | Plugins scaffold (cloud) | Módulos AWS/Azure/GCP; monitor Docker |
| Escala/HA | single‑node | Cluster/orquestração (K8s/Ansible/Docker) |
| Stack | Python | C++/C/Python |
| IA | **AI‑native (obrigatória)** | Rule‑based (IA não é o núcleo) |

**O que extrair (o *porquê*, não código):** (a) **pipeline de eventos plugável**
com decoders/regras/correlação versionados; (b) **conceito de agente de endpoint**
(lifecycle/heartbeat/FIM/inventário/active‑response) para telemetria contínua;
(c) **modelagem de dados** de ativos/eventos/alertas em escala; (d) caminho de
**cluster/HA** quando (e só quando) a escala exigir. **Diferencial do EIGAN a
preservar:** a **IA é o núcleo** (não um add‑on a um rule engine).

---

## 4. Sequenciamento recomendado (mapeado às Fases do roadmap de plataforma)

Ordenado por **valor destravado / esforço**, respeitando os portões:

1. **Fase 1 — Fundações** (prio 1): **Observabilidade de custo/token** (#30, esforço P
   — vitória rápida) + **Event Bus** (#16) + contrato uniforme de **Tool Adapter**
   (#4) + formalizar **DI**. *Gate:* testes+CI verdes, 1 tool real no novo contrato.
2. **Fase 2 — Núcleo multi‑agente E2E** (prio 1): formalizar **Coordinator/Validator/
   Memory** (#5/#6/#9) sobre o `cognitive/` atual; scan real E2E. *Gate:* demo + testes.
3. **Fase 3 — Threat Intel + PoC** (prio 1–2): completar TI (#20/#21) + **validação
   anti‑falso‑positivo/PoC** (#23) com confiança explícita. *Gate:* 1 finding real
   enriquecida e validada.
4. **Fase 4 — Pipeline de eventos + detection** (prio 2): #18/#19. *Gate:* evento
   normalizado→correlacionado→classificado com teste.
5. **Fase 5 — API/WS/SDK/Dashboard** (prio 2): #33/#32 sobre a base já existente.
6. **Fase 6 — Expansão** (prio 3): Reflection/Learning (#7/#8), Knowledge Graph (#22),
   Workflow DAG (#17), Compliance (#25), agentes adicionais — **um por vez, com teste**.
7. **Fase 7 — Hardening** (prio 4): cluster/HA (#38), endpoint agent (#37),
   benchmarks, **reescrita do `CLAUDE.md`** (§30), README final.

**Vitórias rápidas (fazer cedo):** #30 (custo/token, P), corrigir badge/gerar via CI,
consolidar `AIPlanner`. **Riscos de over‑engineering a evitar** (§4.4): Knowledge
Graph, Workflow DAG e cluster **só** quando um requisito real os pedir — não antes.

---

## 5. Conclusão da Fase 0

O EIGAN parte de uma **base ofensiva madura e testada** (446 testes verdes),
com **governança de IA que nem Strix nem Wazuh expõem no mesmo grau** (Policy
Engine + escopo + anti‑injection + redaction). O caminho para "plataforma de
Security Operations" é **aditivo e incremental**: começar pelas fundações baratas
e transversais (observabilidade de custo, event bus), depois formalizar o
multi‑agente e a validação de PoC, e só então a coluna defensiva de eventos e as
camadas de conhecimento/aprendizado — sempre com portões e evidência de teste.
