# ADR-0009 — EIGAN: agente de segurança autônomo dirigido por IA + renome

- **Status:** aceito
- **Data:** 2026-07-11
- **Contexto de:** ADR-0004 (cascata + web), ADR-0007 (núcleo cognitivo),
  ADR-0008 (10 pilares)
- **Superado em parte por:** [ADR-0012](0012-ai-native-mandatory.md) — fixa a IA como
  **obrigatória**. A frase adiante "Sem IA, o produto segue completo" reflete a
  postura AI-opcional anterior e **não vale mais**: sem provedor, o scan é recusado
  (o determinístico é substrato, não "modo sem IA").

## Contexto

O produto antes chamado **VulnForge** tratava a IA como *enriquecedora de
relatório*: a detecção e a orquestração eram 100% determinísticas e a IA só lia o
resultado (CLAUDE.md §3.3 antigo — "a IA nunca executa scanner nem descobre
vulnerabilidade… apenas lê e interpreta"). O ADR-0007 já havia introduzido um
núcleo cognitivo (Planner → Selection → Execution → Feedback → Stop), mas com a IA
restrita a **reordenar** capacidades.

A decisão desta ADR é dupla:

1. **Mudança de papel da IA:** a IA passa a **comandar o scan de ponta a ponta** —
   planeja, decide as capacidades e a ordem, reage às descobertas em ondas
   adaptativas e decide quando parar. É a virada de "AI-assisted" para
   "AI-driven" (agente autônomo).
2. **Renome do produto para EIGAN** — *Enhanced Intelligent Guardian for
   Autonomous Assessment*. Pacote Python `vulnforge` → `eigan`; comando `eigan`
   (alias de transição `vulnforge`).

## Decisão

### Novo modelo (o que muda)

`AgenticPlanner` (`engine/cognitive/planner.py`) substitui o `AIPlanner` como
planner padrão quando há IA disponível:

- **Plano inicial:** a IA propõe as capacidades e a ordem (a partir da estratégia
  do objetivo), com uma condição de parada sugerida.
- **Replanejamento adaptativo:** a cada onda, a IA lê as descobertas recentes +
  tags de contexto e propõe a **próxima onda** de capacidades.
- **Saída estruturada validada (Pydantic v2):** pedimos JSON e o validamos; a
  saída da IA nunca é confiada crua.

O `CognitiveEngine` executa o loop e **transmite a timeline de raciocínio** como
eventos `log` (plano · replan · seleção · execução · stop-hint) — dashboard e
API/WS mostram cada passo justificado. A interface web (`ScanManager`) roda o
`CognitiveEngine` (não mais o `CascadeOrchestrator` direto).

### Invariantes de código que permanecem (cercam a IA, não a limitam)

Estes garantem que o agente autônomo é **legal, verídico e seguro** — exigência
para uso por grandes empresas e auditoria de terceiros:

1. **Gate de autorização/escopo** (`security/scope.py`, `consent.py`): quando a IA
   decide rodar algo, `SafeExecution.enforce` valida o alvo contra o
   `Scope`/perspectiva **antes** de disparar. Alvo fora do autorizado é recusado e
   registrado (`action="skipped"`, "fora de escopo"). Consent gate na API
   preservado (`POST /api/v1/scans` → 403 sem autorização).
2. **Grounding / anti-invenção** (§3.1/§5): a IA só age sobre capacidades que
   **existem de fato** no `PluginRegistry`; ids inventados são descartados por
   validação — nunca viram execução. A IA nunca afirma CVE/CVSS/versão fora das
   evidências.
3. **Piso determinístico + fallback** (§3.4): a cascata declarativa
   (`CascadeGraph`) roda **sempre** como fundo de segurança; a IA acrescenta e
   prioriza sobre ela. Sem chave / erro / JSON inválido do provedor → só o piso
   determinístico, logado. O `DeterministicPlanner` entrega scan + relatório
   completos sem qualquer IA.
4. **Execução segura** (§3.5): a IA escolhe *o quê*; o runner spawna o processo com
   **lista de argumentos, nunca `shell=True`**, nunca concatenação de string.
5. **Escolha da ferramenta é determinística:** a IA decide *capacidades*; o
   `ToolSelector` escolhe a *ferramenta* concreta, com `reasons` auditáveis.

### Contratos (portas)

| Porta | Responsabilidade | Fallback |
|---|---|---|
| `Planner` (`AgenticPlanner`/`DeterministicPlanner`) | plano inicial + replan | determinístico (cascata) |
| `CompletionPort` | `available()` + `complete(system, user)` → texto | ausente ⇒ determinístico |
| `ToolSelector` | capacidade → ferramenta (justificado) | sem ferramenta ⇒ *sugerido* |
| `ExecutionPort` (`SafeExecution`) | valida escopo + roda runner seguro | fora de escopo ⇒ *skipped* |
| `StopCondition` | teto de orçamento/tempo (anti-loop) | sempre ativo |

## Consequências

- **Positivas:** experiência de agente autônomo real (planeja/reage/decide), com
  autonomia **auditável** (timeline sem caixa-preta) e as garantias de
  legalidade/veracidade/segurança intactas. *(A parte "Sem IA, o produto segue
  completo" foi superada por [ADR-0012](0012-ai-native-mandatory.md) — sem provedor,
  o scan é recusado; o determinístico é o substrato que a IA comanda.)*
- **Escopo v1.0 (honesto):** foco **Web + Infraestrutura**, external e internal,
  com **Agente Recon real**; Web/Cloud/AD/Exploitation e memória de longo prazo /
  attack paths / purple loop ficam **scaffold honesto** (visíveis no `doctor`,
  *sugeridos, não executados*).
- **CLAUDE.md** reescrito (§1, §3.3, §7, §8, §18, §19) para o modelo EIGAN,
  mantendo como inegociáveis §3.1/§3.2/§3.4/§3.5.
- **Renome:** `vulnforge` → `eigan` em todo o repositório; versão 0.3.0 → 1.0.0.
  O rename do **repositório no GitHub** é ação de Settings do dono — ver
  `docs/BLOCKERS.md`.

## Como validar

```bash
eigan plan example.com --goal attack-surface        # planner escolhendo/justificando (dry-run)
eigan plan 10.0.0.5 --goal network-assessment --ai  # com IA (fallback se sem chave)
eigan serve                                          # dashboard com timeline de raciocínio
pytest tests/test_cognitive.py                       # IA mockada, grounding, fallback, escopo
```
