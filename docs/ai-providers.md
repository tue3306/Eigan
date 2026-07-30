# Provedores de IA (AI Providers)

O EIGAN é **independente de provedor de IA**. Você escolhe o provedor e o modelo
por variável de ambiente (ou `config/ai.yaml`), e pode adicionar um provedor novo
sem tocar no resto do código. Mas a IA é **obrigatória** (AI-native): sem um provedor
configurado, o scan é **recusado** com erro acionável ([ADR-0012](adr/0012-ai-native-mandatory.md)).
Use um provedor de nuvem **ou o Ollama local** (sem chave, sem custo, offline) — o que é
opcional é *qual* provedor, não *ter* um.

> **Segurança:** chaves vêm **sempre** de variáveis de ambiente / `.env` (fora do
> git, `chmod 600`), nunca de arquivo versionado. Antes de enviar a um provedor
> **externo**, o EIGAN aplica *redaction* de segredos/PII. Ollama é local: nada
> sai da máquina.

## Como configurar (3 formas)

1. **Menu interativo (mais fácil):** `python3 eigan.py` → *Configuração* →
   escolher provedor → colar a chave → informar o modelo. Grava no `.env`.
2. **Wizard:** `python3 eigan.py` → *Novo Scan* — se não houver provedor, ele
   oferece configurar ali mesmo antes do scan.
3. **Manual (`.env` ou ambiente):**
   ```bash
   export EIGAN_AI_PROVIDER=groq        # opcional: força um provedor
   export GROQ_API_KEY=...              # a chave
   export GROQ_MODEL=<modelo>           # o modelo (obrigatório p/ não-Anthropic)
   ```

Sem `EIGAN_AI_PROVIDER`, o EIGAN **auto-detecta** na ordem: Anthropic → OpenAI →
Gemini → OpenRouter → Groq → Together → Azure → Ollama.

## Provedores suportados

| Provedor | `EIGAN_AI_PROVIDER` | Chave (env) | Modelo (env) | Observações |
|---|---|---|---|---|
| Anthropic (Claude) | `anthropic` | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` (padrão verificado) | Só a chave já liga |
| OpenAI (GPT) | `openai` | `OPENAI_API_KEY` | `OPENAI_MODEL` | `OPENAI_BASE_URL` opcional |
| Google Gemini | `gemini` | `GOOGLE_API_KEY` | `GOOGLE_MODEL` | |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `OPENROUTER_MODEL` | gateway p/ 300+ modelos |
| Groq | `groq` | `GROQ_API_KEY` | `GROQ_MODEL` | inferência muito rápida |
| Together AI | `together` | `TOGETHER_API_KEY` | `TOGETHER_MODEL` | modelos open-weight |
| Azure OpenAI | `azure` | `AZURE_OPENAI_API_KEY` | `AZURE_OPENAI_DEPLOYMENT` | + `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_VERSION` |
| Ollama (local) | `ollama` | `OLLAMA_HOST` | `OLLAMA_MODEL` | roda local, sem chave, sem redaction |

> **Anti-invenção (§3.1):** o EIGAN **não fixa um id de modelo** que não foi
> confirmado. Só a Anthropic tem um padrão verificado; os demais **exigem**
> `<PROVIDER>_MODEL`. Escolha o modelo na documentação oficial do provedor. As
> `base_url` OpenAI-compatíveis foram confirmadas na doc oficial e são
> sobrescritíveis por `<PROVIDER>_BASE_URL`.

## Quais APIs usar? (recomendações por tarefa)

O EIGAN usa a IA para **planejar** o scan, **reagir** às descobertas e **narrar**
o relatório. Não existe "melhor" único — combina bem por tarefa:

- **Planejamento e narrativa executiva (raciocínio forte):** modelos de topo da
  **Anthropic (Claude)** ou **OpenAI (GPT)**. É onde a qualidade do plano e do
  laudo mais aparece. Recomendado como provedor principal.
- **Triagem/classificação de findings em volume (rápido e barato):** **Groq**
  (latência baixíssima) ou modelos menores via **OpenRouter/Together**. Ótimos
  para tarefas de alto volume onde raciocínio profundo não é necessário.
- **Flexibilidade / evitar lock-in:** **OpenRouter** dá acesso a muitos modelos
  por uma conta só — bom para experimentar e rotear por custo.
- **Privacidade máxima / dados sensíveis / offline:** **Ollama** (local). Nada sai
  da máquina — não há envio a terceiros, então também não há custo por token.
  Modelos locais raciocinam menos que os de topo, mas mantêm a autonomia básica.
- **Empresas em Azure (governança/residência de dados):** **Azure OpenAI**.

**Regra prática:** um provedor forte (Claude/GPT) como principal + Ollama como
fallback local para dados sensíveis cobre a maioria dos casos. O EIGAN sempre
degrada para o modo determinístico se nenhum estiver disponível.

## Adicionar um provedor novo (extensível)

A arquitetura é modular: implemente a interface padrão e **registre** — nada mais
no código muda (ADR-0010).

```python
# em eigan/ai/provider.py (ou num módulo que rode no import)
from eigan.ai.provider import ProviderSpec, _OpenAICompatProvider, register

class MeuProvider(_OpenAICompatProvider):
    default_base_url = "https://api.meuprovedor.com/v1"   # se for OpenAI-compat

register(ProviderSpec(
    name="meuprovedor",
    label="Meu Provedor",
    provider_cls=MeuProvider,
    key_env="MEUPROVEDOR_API_KEY",
    model_env="MEUPROVEDOR_MODEL",
    base_url_env="MEUPROVEDOR_BASE_URL",
    default_base_url="https://api.meuprovedor.com/v1",
    scan_fit="descreva a adequação ao scanning",
))
```

Se o provedor **não** for OpenAI-compatível, herde de `_HTTPProvider` e implemente
`_complete(system, user) -> str` com o formato dele (veja `GoogleProvider` /
`AnthropicProvider` como exemplos). Depois de registrado, ele aparece no menu, no
`doctor`, na seleção e nos testes — automaticamente.
