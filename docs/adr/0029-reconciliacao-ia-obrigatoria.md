# ADR-0029 — Reconciliação da filosofia IA-obrigatória (fecha a divergência doc×código)

- **Status:** aceito
- **Data:** 2026-07-30
- **Relacionado:** [ADR-0012](0012-ai-native-mandatory.md) (filosofia vigente: IA
  obrigatória), [ADR-0007](0007-cognitive-core-planner.md)/[ADR-0008](0008-agent-platform-ten-pillars.md)/[ADR-0009](0009-eigan-autonomous-agent.md)/[ADR-0010](0010-ai-provider-registry.md)
  (superados em parte); [ADR-0011](0011-policy-guardrail-engine.md) (Policy Engine, o piso)

## Contexto

O repositório carregava **duas filosofias simultâneas** — a mais grave inconsistência
documental do projeto, porque contradiz o princípio nº 1 (não fabricar / honestidade):

- **ADR-0012** (vigente): o EIGAN é **AI-native e AI-obrigatória** — sem provedor, o
  scan é **recusado**; não existe "modo sem IA" que produza um scan.
- **ADR-0007/0008/0009/0010** e várias superfícies (launcher, `docs/ai-providers.md`,
  `docker/README.md`, docstring do `DeterministicEnricher`, `docs/internal/AUDIT.md`)
  ainda afirmavam "sem chave, o produto funciona inteiro" / "IA opcional".

A raiz da confusão é **misturar dois conceitos distintos**:

1. **Substrato determinístico** — `CascadeGraph`, `ToolSelector`, `PolicyEngine`,
   execução segura, `DeterministicPlanner`, `DeterministicEnricher`, exporters/relatório
   de máquina. **Existe, é o piso de segurança que a IA comanda** e a resiliência
   intra-scan (se a IA falha numa etapa, a etapa cai no determinístico). É **intocável**.
2. **"Modo sem IA"** — um caminho de **produto** que rodasse um scan sem provedor.
   **Não existe e não deve existir** (ADR-0012).

## Decisão

Fixar **ADR-0012 como filosofia única** em todo o repositório e separar, em texto e
em teste, o **substrato** (1) do inexistente "modo sem IA" (2):

- **ADRs superados marcados:** ADR-0007/0008/0009/0010 receberam nota de superação
  explícita apontando para o ADR-0012, e a frase "sem chave, o produto funciona inteiro"
  foi corrigida para a leitura de substrato.
- **Superfícies de usuário alinhadas:** launcher (`eigan.py`), `docs/ai-providers.md`,
  `docker/README.md`, docstring do `DeterministicEnricher` (`ai/provider.py`) e
  `docs/internal/AUDIT.md` deixaram de afirmar que o produto/scan funciona sem provedor.
- **Entry points de produto continuam gated** (nenhum caminho produz scan sem provedor):
  - CLI: `execute_scan` e `plan_scan` (modo execução) chamam `require_provider()` **antes**
    de termo/consent/rede → `AIProviderRequired` acionável.
  - API: `POST /api/v1/scans` → **HTTP 428** sem provedor.
  - Exceção legítima: `plan --dry-run` (preview que nada executa) não exige provedor.
- **Testes de "sem IA" relabelados para testes de substrato:** os testes que constroem
  o `CognitiveEngine` **sem `CompletionPort`** exercitam o `DeterministicPlanner` (o piso),
  não "operação de produto sem IA" — comentários/nome atualizados em `test_cognitive.py`.
- **CI permanece hermético** (sem rede, sem chave) exercitando o **substrato**
  (`DeterministicPlanner` / `CompletionPort` stub) — não um "modo sem IA". O produto
  segue AI-obrigatório.

## Consequências

- **Positivas:** uma única filosofia declarada em todo o repositório; garantia, agora
  **verificada por teste**, de que nenhum caminho de produto produz scan sem provedor; o
  substrato preservado e claramente rotulado; CI hermético sem contradizer o ADR-0012.
- **Custos/limites:** ADRs antigos guardam a nota de superação em vez de reescrita (o
  histórico de decisão é imutável; a nota o torna navegável). A suíte de integração real
  (DVWA/Juice Shop) segue como item bloqueado por Docker (ver `docs/BLOCKERS.md` #8).

## Como validar

```bash
pytest tests/test_ai_native_gate.py     # entry points CLI recusam sem provedor; dry-run permitido
pytest tests/test_api_scan.py -k ai_provider   # API → 428 sem provedor
pytest tests/test_ai_provider.py -k require_provider   # require_provider levanta AIProviderRequired
# nenhuma superfície afirma "o produto funciona sem IA":
grep -rniE "sem chave.*funciona|IA opcional|modo sem IA que|roda 100% no modo" docs src eigan.py
```
