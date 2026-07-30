# ADR-0010 — Registro modular de provedores de IA (independência de provedor)

- **Status:** aceito
- **Data:** 2026-07-11
- **Relacionado:** ADR-0009 (agente autônomo), §7 do CLAUDE.md

## Contexto

O EIGAN é AI-native mas AI-opcional. A camada de IA precisa ser **independente de
um único provedor**: o usuário deve poder trocar entre Anthropic, OpenAI, Gemini,
OpenRouter, Groq, Together, Azure OpenAI e Ollama (local) por configuração, e
adicionar um provedor novo **sem alterar o resto do código**.

## Decisão

Um **registro de provedores** em `ai/provider.py`:

- Interface padrão `AIProvider` (+ base `_HTTPProvider` e `_OpenAICompatProvider`).
- `ProviderSpec` descreve cada provedor: classe, envs de credencial/modelo/base_url,
  se é externo (redaction), modelo padrão (só onde verificado) e nota de adequação.
- `register(spec)` / `list_providers()` — **ponto de extensão único**. Adicionar
  provedor = implementar `_HTTPProvider` (ou reusar `_OpenAICompatProvider`) e
  registrar um `ProviderSpec`. Nada mais muda.
- Seleção: `EIGAN_AI_PROVIDER` (ou `default:` em `config/ai.yaml`) escolhe
  explicitamente; senão auto-detecção por prioridade. `default_provider()` resolve.

### Compatibilidade OpenAI

A maioria dos provedores modernos fala o schema **OpenAI Chat Completions**;
OpenRouter/Groq/Together herdam de `_OpenAICompatProvider` mudando só a `base_url`
(confirmada na doc oficial — Groq `console.groq.com/docs/openai`, OpenRouter
`openrouter.ai/docs`, Together `docs.together.ai`), **sobrescritível por
`<PROVIDER>_BASE_URL`** para não fixarmos um endpoint que possa mudar (§3.1).
Azure OpenAI difere (auth `api-key`, deployment na URL, `api-version` por env).

### Anti-invenção (§3.1)

Nenhum `model_id` é fabricado: só a Anthropic tem padrão verificado; os demais
exigem `<PROVIDER>_MODEL`. Sem modelo, o provedor fica inativo e o produto segue
100% determinístico. Chaves só por variável de ambiente (§5); nunca em arquivo
versionado (o onboarding grava em `.env`, fora do git, `chmod 600`).

## Consequências

- Trocar de provedor é uma variável de ambiente; adicionar provedor é um
  `ProviderSpec` — extensível sem tocar no núcleo (mesmo espírito de plugins).
- Ver `docs/ai-providers.md` (guia de uso + quais APIs recomendadas para scanning).
- Fallback determinístico intacto como **substrato** que a IA comanda. *(Superado por
  [ADR-0012](0012-ai-native-mandatory.md): sem provedor **não há scan** — o
  determinístico não é um "modo sem IA".)*

## Como validar

```bash
pytest tests/test_ai_provider.py         # registro, seleção, round-trip OpenAI-compat
eigan doctor                             # mostra o provedor ativo + modelo (ou o que falta)
```
