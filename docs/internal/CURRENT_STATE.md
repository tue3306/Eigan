# CURRENT_STATE — Estado atual do EIGAN (Fase 0)

> **Propósito.** Retrato *verificado contra o código real* do que o EIGAN é hoje,
> antes de qualquer trabalho do roadmap de plataforma. Cada afirmação factual aqui foi
> conferida no repositório (arquivos, testes executados, CI). Onde não verifiquei,
> está marcado `NÃO VERIFICADO`. Nada de features inventadas (regra de veracidade §2).
>
> **Método.** Leitura de `src/eigan/**`, `plugins/**`, `docs/**`, `tests/**`,
> `pyproject.toml`, `.github/workflows/**`; execução real de `pytest`.
> **Data:** 2026‑07‑14 · **Commit base:** `b7fdcba` (main, sincronizado com origin).

---

## 1. O que o EIGAN é, hoje

EIGAN é um **agente de segurança autônomo dirigido por IA** (Red · Blue · Purple),
em **Python 3.11+**, com um **Core Engine próprio** e arquitetura de **plugins/
capabilities** com auto‑discovery. A IA planeja o scan em *capacidades*, reage às
descobertas em ondas e replaneja; a execução real passa por *plumbing* seguro
(subprocess com lista de args), pelo **gate de escopo** e pelo **Policy Engine**.

**Escala de código (verificada):** `src/eigan/` = **12.543 linhas** de Python em
**~76 módulos**, mais **38 plugins** e **~60 arquivos de teste**.

**Testes (execução real, não estimativa):**

```
$ python -m pytest -q
446 passed, 15 skipped in 4.93s
```

Os 15 *skipped* correspondem a plugins/agentes de **scaffold honesto** (roadmap),
que o registry descobre mas que **não executam** até serem implementados (§3.6).

> ⚠️ **Drift doc↔realidade encontrado:** o badge do `README.md` diz
> `testes-234 passed`; o número real é **446 passed**. Corrigir no marco de docs.

---

## 2. Pontos de entrada (entrypoints)

| Entrypoint | Origem | Papel |
|---|---|---|
| `eigan` (CLI) | `pyproject` → `eigan.cli.main:main` | CLI Click: `scan`, `report`, `serve`, `doctor`, `feeds`, `plan`, wizard |
| `python -m eigan` | `src/eigan/__main__.py` | Idêntico ao CLI |
| `vulnforge` | `eigan.cli.main:deprecated_alias` | Alias de transição depreciado (avisa e delega) |
| `./eigan` (bash) | script raiz (273 B) | Atalho `exec python3 eigan.py "$@"` |
| `python3 eigan.py` | `eigan.py` raiz (~13 KB, só stdlib) | **Launcher "unzip e um comando"**: checa Python, cria `.venv`, instala, gera `.env`, abre o menu |

## 3. Dependências (verificadas em `pyproject.toml`)

- **Runtime:** `pydantic>=2`, `pyyaml>=6`, `click>=8.1`, `jinja2>=3.1`,
  `fastapi>=0.110`, `uvicorn>=0.27`.
- **Extras:** `pdf` (`weasyprint`), `ai` (`httpx`), `tui` (`textual`, `rich`),
  `dev` (`pytest`, `pytest-cov`, `ruff`, `mypy`, `httpx`).
- Licença declarada: **Apache‑2.0**. Python: **≥3.11**.

## 4. CI/CD (verificado em `.github/workflows/`)

- **`ci.yml`** (push em `main` + PRs): `ruff check` + `ruff format --check` +
  `mypy src` + `pytest --cov` · job **`smoke-install`** (instala o pacote limpo e
  roda `eigan --version`, `eigan doctor`, `eigan plan example.com`).
- **`publish.yml`**: publicação no PyPI via **Trusted Publishing (OIDC)** ao criar
  Release — **inerte** até o dono configurar o trusted publisher (sem segredo no repo).

---

## 5. Arquitetura em camadas (o que existe de verdade)

```
src/eigan/
  capability.py · perspective.py          # domínio de 1ª classe (Enum de capacidades; EXTERNAL/INTERNAL)
  findings/     schema, store (SQLite), dedup/correlação
  engine/       orchestrator, pipeline, registry, plugin, risk, correlation, feeds,
                base, cascade, blue, credentials, events, tuning, wordlists
  engine/cognitive/  goal, planner (Determinístico/AI/Agentic), selection, agent,
                     feedback, engine    ← núcleo agêntico
  analysis/     inventory, attack (MITRE), compliance, diff, merge, purple, engine
  report/       deterministic (HTML/PDF), exporters (JSON/CSV/SARIF), corporate,
                markdown, remediation, pdf_support
  ai/           provider (multi‑provedor), context, conversation, prompts,
                remediation, sanitize (anti prompt‑injection)
  knowledge/    loader (skills)
  security/     scope, consent, onboarding, apitoken, ssrf
  policy/       engine, impact               ← Policy/Guardrail Engine (ADR‑0011)
  api/          app (FastAPI /api/v1 + WS), scan_manager
  cli/          main, doctor, menu, wizard, session, reporting, ui, tui
plugins/<red|blue|purple>/...              # 38 plugins (metadata.yaml + runner/parser)
knowledge/      skills/ (SKILL.md), attack/techniques.yaml, compliance/mappings.yaml
config/  docker/  web/ (landing)  docs/
```

### 5.1 Núcleo cognitivo — **real e maduro** (não é stub)

`engine/cognitive/` implementa o loop `Goal → Planner → [Agent → ToolSelector →
Execution] → Feedback → replan → StopCondition`, com:

- **Três planners plugáveis** (`planner.py`, 484 linhas): `DeterministicPlanner`
  (piso/fallback), `AIPlanner` (a IA reordena), **`AgenticPlanner`** (a IA comanda
  o plano fim a fim: propõe o plano inicial e a próxima onda por descoberta).
- **Grounding real:** ids inventados pela IA são descartados por validação; saída
  da IA é **JSON validado com Pydantic v2**; qualquer falha cai no determinístico.
- **Defesa anti prompt‑injection** (ADR‑0016): findings do alvo são tratados como
  **dados não‑confiáveis**, neutralizados antes de irem ao prompt.
- **`CognitiveEngine`** (`engine.py`, 695 linhas): rastro auditável (`DecisionEntry`),
  streaming de eventos, **Policy Engine em cada ação** (executar/HITL/recusar),
  **gate de escopo por alvo**, **expansão de alvos dirigida por descoberta**
  (ADR‑0018), **persistência incremental** (ADR‑0017, durável a kill/timeout),
  dedup + risk scoring no finalize.

### 5.2 IA multi‑provedor — **8 provedores** (verificado em `ai/provider.py`, 817 linhas)

Registro modular `ProviderSpec`: **anthropic, openai, gemini, openrouter, groq,
together, azure, ollama** (local). Adicionar provedor = registrar um spec.

### 5.3 Segurança do produto — implementada

Gate de escopo (`security/scope.py`), consent gate, onboarding de IA, **auth de
API obrigatória** (ADR‑0014), **blindagem de SSRF** (redirect/metadata/DNS‑rebinding,
ADR‑0015), **sanitização anti prompt‑injection** (ADR‑0016), Policy/Guardrail
Engine com `ImpactClass` + HITL (ADR‑0011).

### 5.4 API + Dashboard — real

FastAPI versionada `/api/v1` com ~30 rotas (scans, findings, inventory, attack,
compliance, chat, remediation, merge, **purple**, **blue**, jobs, report, assets,
stats, setup, meta, health) + **WebSocket** `/ws/scans/{job_id}/progress` +
**token auth** em middleware. SPA estática servida em `/` (`api/static/`).

### 5.5 Relatórios — HTML/PDF/JSON/CSV/SARIF

`report/deterministic.py` (HTML→PDF via WeasyPrint, opcional), `exporters.py`
(JSON/CSV/**SARIF** determinísticos), `corporate.py`/`remediation.py` (narrativas
por IA). Findings normalizados (`findings/schema.py`), store SQLite, dedup por
`fingerprint`, risk scoring com feeds EPSS/KEV/CVE (`engine/risk.py`, `feeds.py`).

---

## 6. Plugins — inventário verificado (38 total)

| Perspectiva | Total | Com teste de parser (fixtures reais) | Scaffold / sem cobertura |
|---|---|---|---|
| **red** | 27 | 20 | 7 |
| **blue** | 8 | 3 | 5 |
| **purple** | 3 | 0 | 3 |
| **Total** | **38** | **23** | **15** |

- **Com parser + testes (23):** nmap, nmap_nse, naabu, httpx, subfinder, amass,
  dnsx, katana, ffuf, gowitness, nikto, whatweb, nuclei, dalfox, sqlmap, testssl,
  enum4linux, ldapsearch, wpscan, exposure (red) · trivy, grype, log_analysis (blue).
- **Scaffold honesto / sem teste de parser (15):** feroxbuster, active‑directory,
  burp, cloud, exploitation, password‑audit, wireless (red) · detection‑rules,
  incident‑response, malware‑analysis, siem, threat‑hunting (blue) ·
  attack‑simulation, control‑validation, detection‑validation (purple).
  **Fonte autoritativa do estado "construído × roadmap": `eigan doctor`.**

O **Core não muda** para somar plugin (auto‑discovery via `metadata.yaml`,
ADR‑0001/0003). Isto é uma força já entregue.

---

## 7. Documentação e governança já presentes

- **24 ADRs** (`docs/adr/0001‑0024`) cobrindo plugin/capability, risk/feeds,
  cascata, planner cognitivo, provider registry, IA obrigatória, policy engine,
  auth de API, SSRF, prompt‑injection, persistência, expansão de alvos, blue/purple,
  remediação por IA, etc.
- `docs/architecture.md`, `ROADMAP.md`, `AUDIT.md`, `BLOCKERS.md`, `DECISIONS.md`,
  `ai-providers.md`, `design/` (personas, components), `roadmap/`.
- Comunidade: `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
  `CHANGELOG.md` (Keep a Changelog), `LICENSE` (Apache‑2.0), `install.sh`, `docker/`.
- `.gitignore` correto: `eigan.db*`, `.coverage`, `report_scan_*`, `.env`,
  `eigan-screenshots/`, caches — **nenhum artefato de runtime é versionado**
  (confirmado: `git ls-files` não rastreia nenhum deles).

---

## 8. Higiene de código

- **Lint/format:** `ruff` limpo (CI exige `ruff check` + `ruff format --check`).
- **Types:** `mypy src` no CI.
- **Testes verdes:** 446 passed / 15 skipped, ~5 s.
- **Sem `shell=True`** no plumbing (execução por lista de args — política do §5).
- **Sem stubs mentindo:** módulos não construídos são scaffold roadmap explícito.

---

## 9. Lacunas honestas do estado atual (detalhe na GAP_ANALYSIS)

Relativo ao alvo do roadmap de plataforma (plataforma AI‑Native de Security Operations):

1. **Observabilidade de custo/token e tracing distribuído** — *ausente*. Não há
   contagem de tokens, custo por execução, nem tracing (`grep` por
   `token_usage|cost|tracing|opentelemetry|prometheus` no `src/` → nenhum módulo).
   O que existe é logging estruturado + eventos de progresso.
2. **Event bus real (pub/sub)** — *ausente*. `engine/events.py` é um `EventSink`
   simples (sink de progresso), não um barramento desacoplado com tópicos.
3. **Workflow engine por grafo (DAG)** — *ausente*. O plano é uma **fila linear**
   de capacidades (com replan por onda), não um DAG com dependências/paralelismo
   explícitos e estado retomável.
4. **Threat Intel como camada RAG (CVE/CWE)** — *parcial*. Há enriquecimento por
   feeds (EPSS/KEV/CVE em `risk.py`/`feeds.py`), mas **não** um RAG/knowledge base
   pesquisável sobre CVE/CWE.
5. **Knowledge Graph** — *ausente* (há `knowledge/` de *skills*, não um grafo).
6. **Camadas de Reflection / Learning / Memory persistente entre execuções** —
   *ausentes* (o replan é intra‑scan; não há aprendizado entre pentests).
7. **EIGAN Agent de endpoint** (conceito Wazuh: lifecycle/heartbeat/FIM/inventário)
   — *ausente* (EIGAN é scanner/agente central, não tem agente de endpoint).
8. **Blue/Purple** — *parcialmente scaffold* (engine blue existe; vários plugins
   defensivos e de simulação ainda são roadmap).
9. **Detection pipeline de eventos ao estilo SIEM** (decoders/rules/correlação de
   *eventos*, não de *findings*) — *parcial/ausente*.

Nenhuma dessas lacunas é um bug: são **escopo ainda não construído**. O que existe
é sólido, testado e coerente com o `CLAUDE.md` atual.

---

## 10. Veredito

O EIGAN **hoje** é um **agente ofensivo (pentest‑first) AI‑native, funcional e
testado**, com núcleo cognitivo maduro, plumbing seguro, policy engine, API +
dashboard e relatórios. É uma **base real** — não um protótipo. O roadmap de plataforma
o expande para uma **plataforma de Security Operations** (coluna defensiva de
eventos, threat‑intel/RAG, workflow por grafo, observabilidade de custo,
knowledge graph, agente de endpoint, learning). Ver `TARGET_ARCHITECTURE.md` e
`GAP_ANALYSIS.md`.
