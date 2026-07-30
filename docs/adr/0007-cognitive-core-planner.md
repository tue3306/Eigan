# ADR-0007 — Núcleo Cognitivo: Planner, Capabilities e Agentes

- **Status:** aceito
- **Data:** 2026-07-10
- **Relaciona-se com:** [ADR-0001](0001-plugin-capability-architecture.md)
  (capabilities), [ADR-0004](0004-cascade-orchestration-and-web-ui.md) (cascata
  determinística), [ADR-0002](0002-risk-engine-feeds.md) (risco/feeds)
- **Superado em parte por:** [ADR-0012](0012-ai-native-mandatory.md) — a IA é
  **obrigatória**. O "fallback determinístico" abaixo permanece como **substrato**
  (piso de segurança + resiliência intra-scan), não como "modo sem IA": sem provedor,
  o scan é recusado.

## Contexto

O EIGAN já executa um pipeline determinístico por *capability/perspectiva*
(`engine/pipeline.py` + `Orchestrator`) e uma cascata dirigida por descoberta
(`engine/cascade.py`). Falta a camada **orientada por objetivo** (goal-driven):
o usuário informa um objetivo ("avaliar a superfície de ataque deste domínio") e
o sistema decide **quais capacidades** usar, **em qual ordem**, **qual ferramenta
executar para cada capacidade**, quando **replanejar** e quando **parar** — sem o
usuário pensar em ferramentas.

Restrições inegociáveis do CLAUDE.md que moldam a decisão:

- **A IA nunca executa scanner nem descobre vulnerabilidade** (§3.3). A fronteira
  é explícita: *a IA escolhe Capability; o Tool Selection Engine escolhe a
  ferramenta; o Execution Engine executa; o Feedback retorna; o Planner decide de
  novo.* Nenhum atalho da IA para execução direta.
- **Todo recurso de IA tem fallback determinístico** (§3.4/§7): sem provedor/erro, o
  Planner cai no plano determinístico + grafo de cascata (o **substrato**). *(Superado
  por [ADR-0012](0012-ai-native-mandatory.md): isso é resiliência intra-scan, não um
  "modo sem IA" — sem provedor, o scan é recusado.)*
- **Autorização/escopo são pré-condição de toda ação ativa** (§2): o consent gate
  precede a execução; `scope.enforce` roda por alvo, defesa em profundidade.
- **Auditabilidade total, nada de caixa-preta** (§3.4): *toda* escolha é logada e
  justificada (capacidade, ferramenta escolhida, motivos, alternativas).
- **Core intacto ao somar módulo** (§6): registrar novas capacidades/ferramentas/
  agentes não reescreve o núcleo — 100+ módulos sem tocar no loop.

## Decisão

Introduzir o subpacote `engine/cognitive/`, uma camada **acima** do
`Orchestrator`, com contratos (portas) estáveis e implementações plugáveis. O
fluxo obrigatório:

```
Goal → Planner → Plan (capabilities) → [Agent → Tool Selection → Execution]
     → Feedback → Planner (replan) → Stop Condition
```

### Contratos (portas) — o que pluga sem reescrever o núcleo

| Contrato | Onde | Responsabilidade | Fronteira |
|---|---|---|---|
| **Goal** | `goal.py` | Objetivo do usuário + alvos + perspectiva + `Budget` (limites de parada). Dado imutável. | Domínio puro. |
| **Planner** | `planner.py` (Protocol) | `initial_plan(goal)` e `replan(goal, state, plan)`. Decide **capacidades**, nunca ferramentas nem comandos. | `DeterministicPlanner` (fallback) e `AIPlanner` (só reordena capacidades válidas; fallback determinístico). |
| **Capability Registry** | `PluginRegistry` (ADR-0001) via `CapabilityRegistryPort` | Resolve, por capacidade+perspectiva, os plugins que a implementam. **Já existe** — a camada cognitiva consome a porta, não a concreta. | Infra descoberta por metadados. |
| **Tool Selection Engine** | `selection.py` → `ToolSelector` | Dada uma capacidade + `SelectionContext`, **ranqueia** os plugins disponíveis e escolhe um, com `ToolChoice(reasons, alternatives)`. Determinístico. | Escolha nunca fixa; sempre justificada. |
| **Agents** | `agent.py` → `Agent`/`AgentRegistry` | Especialidade que **agrupa capacidades** (Recon, Web, Network, Cloud, AD, Container…). Roteia a capacidade ao agente dono. | Recon **real**; demais **scaffold honesto** (`built=False`) — aparecem no `doctor` como "sugerido, não executado". |
| **Execution Engine** | `engine.py` → `ExecutionPort`/`SafeExecution` | Executa a escolha via `spec.scan` (subprocess seguro, lista de args). `scope.enforce` antes de cada alvo. | Reusa a execução segura existente; nenhuma ferramenta roda por conta própria. |
| **Feedback** | `feedback.py` → `Feedback`/`ScanState` | Registra ferramenta, duração, sucesso/erro, findings e novas evidências; alimenta o replan. | Determinístico e serializável para o log. |
| **Stop Condition** | `feedback.py` → `StopCondition` | Encerra por: objetivo/plano exaurido, sem nova evidência, orçamento de capacidades, tempo, interrupção. | Limites do `Budget` (usuário controla). |

### Como cada peça respeita a fronteira IA×execução

- **`AIPlanner` só ordena capacidades.** O prompt recebe o objetivo, a lista de
  capacidades **válidas** (valores do enum `Capability`) e um resumo das
  evidências; devolve uma **ordem** dessas capacidades. Qualquer id inventado é
  descartado (anti-invenção §3.1). Ele **nunca** devolve nome de ferramenta,
  comando ou CVE. Em erro/instabilidade, cai para a ordem do `DeterministicPlanner`.
- **`ToolSelector` (determinístico) escolhe a ferramenta** a partir de sinais no
  `metadata.yaml` (`selection:` — `speed/accuracy/resource_usage/preferred_when/
  avoid_when`, heurísticas operacionais **nossas**, não fatos externos) + a
  disponibilidade real + o contexto (perspectiva, tags de SO/serviço/tecnologia,
  preferência velocidade×precisão). Empate resolvido por nome (estável).
- **Replan determinístico reusa a cascata** (`CascadeGraph`): novas evidências
  disparam capacidades adicionais de forma pura e justificada. Ferramentas
  sugeridas mas não instaladas/roadmap entram no log como *sugeridas, não
  executadas*.

### Sinais de seleção no metadata (`selection:`)

Bloco **opcional** por plugin. Defaults honestos (`medium`, listas vazias). São
**heurísticas de tuning operacional**, explicitamente **não** benchmarks
autoritativos — por isso não caem sob a regra anti-invenção de fatos externos
(CVE/CVSS/versão), mas ficam versionados e auditáveis como configuração.

```yaml
selection:
  speed: high            # low | medium | high
  accuracy: medium
  resource_usage: medium
  preferred_when: [linux, http]      # tags de contexto que favorecem
  avoid_when: [low_bandwidth]        # tags que desfavorecem/excluem
```

## Alternativas consideradas

1. **A IA emite comandos/ferramentas diretamente.** Rejeitado: viola §3.3, vira
   caixa-preta e acopla o produto a uma chave de API. A IA fica na camada de
   *decisão de capacidade* e de *interpretação*, nunca de execução.
2. **Planner monolítico com sequência fixa por objetivo.** Rejeitado: não
   replaneja com base em descoberta e duplicaria a cascata. Reusamos o
   `CascadeGraph` como motor de replanejamento determinístico.
3. **Reescrever o `Orchestrator` para ser goal-driven.** Rejeitado: quebraria o
   Core estável. A camada cognitiva **envolve** o pipeline via portas, como o
   `CascadeOrchestrator` já faz (ADR-0004).

## Consequências

- Novo objetivo = mapear `GoalKind → capacidades` (dado declarativo). Nova
  ferramenta = criar plugin com `capabilities` + `selection:` — o Planner passa a
  usá-la **sem** alteração no núcleo. Novo agente real = marcar `built=True` e
  implementar sua especialidade.
- **Escopo desta entrega (fundação real + scaffold honesto):** `DeterministicPlanner`,
  `AIPlanner`, `ToolSelector`, `StopCondition`, `CognitiveEngine` e o
  **Recon Agent** são reais e rodam ponta a ponta (subfinder → dnsx →
  naabu/nmap → httpx → nuclei, com seleção justificada entre `naabu` e `nmap`
  para `port_discovery`). Web/Network/Cloud/AD/Container/Exploitation ficam como
  agentes **scaffold** (`built=False`), visíveis no `doctor`, ainda não operantes.
- Comando de verificação: `eigan plan <alvo> --goal attack-surface --dry-run`
  mostra o plano e a seleção justificada **sem executar** (sem consent). Sem
  `--dry-run`, o consent gate precede a execução real.
