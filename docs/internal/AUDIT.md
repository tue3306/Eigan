# Auditoria arquitetural — EIGAN (PASSO 0)

> Registro do estado do repositório **no início** da evolução para plataforma
> modular Red/Blue/Purple. Base para os ADRs em `docs/adr/`.

## 1. O que já existia (v0.1.0) e foi preservado

A fundação era sólida e seguia Clean Architecture de fato:

| Camada | Módulo | Responsabilidade |
|---|---|---|
| Domínio (sem I/O) | `findings/schema.py` | Schema normalizado `Finding` + `fingerprint` para dedup. |
| Domínio | `perspective.py` | **Perspective (EXTERNAL/INTERNAL) como conceito de 1ª classe** — dirige guardrail, rate limit e ferramentas por configuração. |
| Domínio/Segurança | `security/scope.py`, `security/consent.py` | Guardrail de escopo + consent gate (barreira legal). |
| Aplicação | `engine/orchestrator.py`, `engine/pipeline.py` | Orquestração por perspectiva; pipeline como grafo de estágios. |
| Infra | `engine/adapters/*` | 6 adapters reais: nmap, nuclei, naabu, dnsx, subfinder, httpx. |
| Infra | `findings/store.py` | Persistência SQLite (Repository Pattern). |
| Infra | `ai/provider.py` | IA **obrigatória** (AI-native, ADR-0012); o determinístico é substrato. |
| Infra | `knowledge/loader.py` | Base de conhecimento (padrão `SKILL.md`). |
| Infra | `report/deterministic.py` | Relatório HTML→PDF (WeasyPrint opcional). |
| Interface | `cli/main.py` (click), `api/app.py` (FastAPI) | CLI headless + API REST `/api/v1`. |

Estado de qualidade medido: **36 testes passando, `ruff` limpo**, `mypy` ausente
do ambiente. Python 3.13 disponível (o alvo declarado é 3.11+).

## 2. Lacunas frente à visão de plataforma (Red/Blue/Purple, 100+ módulos)

1. **Sem arquitetura de plugins.** Os adapters viviam num `dict _REGISTRY`
   fixo dentro do orquestrador — adicionar ferramenta exigia **editar o Core**.
2. **Sem `Capability` como contrato.** O pipeline referenciava ferramentas por
   nome, não capacidades intercambiáveis.
3. **Sem Risk Engine** (CVSS/EPSS/KEV/exploit) nem correlação de cadeias.
4. **Sem UX de produto:** faltavam wizard interativo, `doctor`, consent inline,
   zero-config, `.env.example`.
5. **Relatórios incompletos:** só HTML/PDF; faltavam JSON/CSV/SARIF e o modelo
   Executivo.
6. **Sem estrutura Red/Blue/Purple** e sem profissionalização do repo (landing,
   docs/architecture, CONTRIBUTING/SECURITY, templates, CHANGELOG).

## 3. Veredito da avaliação

> A arquitetura atual **suporta crescer para 100+ módulos?** Não sem uma camada
> de plugins/capabilities. A base (domínio limpo, perspectiva como 1ª classe,
> schema normalizado) é excelente e é **mantida**; a evolução é **aditiva**,
> preservando testes verdes a cada incremento.

Decisões derivadas registradas em:
- [ADR-0001](../adr/0001-plugin-capability-architecture.md) — Plugins + Capabilities.
- [ADR-0002](../adr/0002-risk-engine-feeds.md) — Risk Engine e feeds sem invenção.
- [ADR-0003](../adr/0003-plugins-directory-layout.md) — Onde os plugins vivem.
