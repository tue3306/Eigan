"""Testes da camada de IA: redaction, grounding, parsing, seleção e fallback.

A chamada HTTP fica isolada em ``_complete``/``_post`` — o round-trip da Anthropic
é exercitado com ``httpx.MockTransport`` (sem rede). Sem chave/modelo, o produto
segue 100% determinístico (o fallback nunca depende de IA).
"""

import json

import pytest

from eigan.ai.provider import (
    _LOCAL_TIMEOUT,
    PROVIDERS,
    AIProvider,
    AnthropicProvider,
    Enricher,
    Explanation,
    GroqProvider,
    OllamaProvider,
    OpenAIProvider,
    ProviderSpec,
    _build_prompts,
    _parse_explanation,
    default_provider,
    list_providers,
    redact,
    register,
)
from eigan.findings.schema import Finding, Severity
from eigan.knowledge.loader import KnowledgeBase

_AI_ENV = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "OLLAMA_HOST",
    "ANTHROPIC_MODEL",
    "OPENAI_MODEL",
    "GOOGLE_MODEL",
    "OLLAMA_MODEL",
    "GROQ_API_KEY",
    "GROQ_MODEL",
    "OPENROUTER_API_KEY",
    "OPENROUTER_MODEL",
    "TOGETHER_API_KEY",
    "TOGETHER_MODEL",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_VERSION",
    "EIGAN_AI_PROVIDER",
)


def _finding():
    return Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        affected_asset="http://alvo/app",
        source_tool="nuclei",
        cwe="CWE-89",
        description="Parâmetro id vulnerável.",
    )


@pytest.fixture(autouse=True)
def _clean_ai_env(monkeypatch):
    for key in _AI_ENV:
        monkeypatch.delenv(key, raising=False)


# --------------------------------------------------------------------------- #
# Redaction (§7)
# --------------------------------------------------------------------------- #
def test_redact_strips_secrets_and_pii():
    out = redact("password: hunter2 contato ana@empresa.com chave AKIAABCDEFGHIJKLMNOP")
    assert "hunter2" not in out
    assert "ana@empresa.com" not in out
    assert "AKIAABCDEFGHIJKLMNOP" not in out
    assert "[REDACTED]" in out


def test_build_prompts_grounds_on_finding_and_context():
    system, user = _build_prompts(_finding(), "remediação da skill CWE-89")
    assert "CWE-89" in user
    assert "remediação da skill" in user
    assert "NUNCA invente" in system  # instrução anti-invenção no prompt


def test_parse_explanation_splits_sections():
    exp = _parse_explanation("EXPLICAÇÃO: é grave\nREMEDIAÇÃO: use prepared statements", _finding())
    assert exp.ai_generated is True
    assert exp.text == "é grave"
    assert "prepared statements" in exp.remediation


# --------------------------------------------------------------------------- #
# Seleção de provedor por ambiente
# --------------------------------------------------------------------------- #
def test_default_provider_none_without_config():
    assert default_provider() is None


def test_require_provider_raises_without_config():
    # AI-native (§3.4/ADR-0012): sem provedor, recusa acionável (não None, não crash).
    from eigan.ai.provider import AIProviderRequired, require_provider

    with pytest.raises(AIProviderRequired) as exc:
        require_provider()
    assert "provedor de IA" in str(exc.value)
    assert "ollama" in str(exc.value).lower()  # mensagem aponta a opção local


def test_require_provider_returns_when_configured(monkeypatch):
    from eigan.ai.provider import require_provider

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    assert isinstance(require_provider(), AnthropicProvider)


def test_default_provider_anthropic_from_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    provider = default_provider()
    assert isinstance(provider, AnthropicProvider)
    assert provider.available() is True


def test_default_provider_openai_uses_tier_model(monkeypatch):
    # OpenAI resolve o modelo pelo NÍVEL (tier) — ids verificados na API real —,
    # então não exige mais OPENAI_MODEL. Um id explícito ainda sobrepõe o tier.
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("EIGAN_AI_TIER", raising=False)  # default: medium
    monkeypatch.delenv("EIGAN_AI_PROVIDER", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
    prov = default_provider()
    assert isinstance(prov, OpenAIProvider)
    assert prov._model == "gpt-5"  # nível medium → gpt-5
    monkeypatch.setenv("EIGAN_AI_TIER", "low")
    assert default_provider()._model == "gpt-5-mini"  # nível baixo
    monkeypatch.setenv("OPENAI_MODEL", "gpt-custom")  # override de power-user vence
    assert default_provider()._model == "gpt-custom"


# --------------------------------------------------------------------------- #
# Registro modular de provedores (§ AI Providers)
# --------------------------------------------------------------------------- #
def test_registry_lists_all_expected_providers():
    names = {s.name for s in list_providers()}
    # o pedido: independência de provedor único, extensível.
    assert {
        "anthropic",
        "openai",
        "gemini",
        "openrouter",
        "groq",
        "together",
        "azure",
        "ollama",
    } <= names


def test_explicit_provider_selection_via_env(monkeypatch):
    # o usuário escolhe o provedor por env, mesmo com outra chave presente.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")  # anthropic tem prioridade…
    monkeypatch.setenv("GROQ_API_KEY", "gsk-x")
    monkeypatch.setenv("GROQ_MODEL", "algum-modelo")
    monkeypatch.setenv("EIGAN_AI_PROVIDER", "groq")  # …mas a escolha explícita vence
    assert isinstance(default_provider(), GroqProvider)


def test_groq_uses_confirmed_openai_compatible_base_url():
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = GroqProvider(model="algum-modelo", credential="gsk", client=client)
    assert provider.complete("s", "u") == "ok"
    assert captured["url"] == "https://api.groq.com/openai/v1/chat/completions"


def test_json_mode_sends_response_format_only_when_requested():
    # json_mode=True → response_format json_object (saída estruturada garante JSON
    # válido; corrige o JSON malformado do GPT-5 que forçava o fallback do Planner).
    # json_mode=False (default) → sem response_format (narrativas seguem prosa).
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        import json as _json

        captured["payload"] = _json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    def _mk():
        client = httpx.Client(transport=httpx.MockTransport(handler))
        return GroqProvider(model="m", credential="k", client=client)

    _mk().complete("s", "diga json", json_mode=True)
    assert captured["payload"]["response_format"] == {"type": "json_object"}

    _mk().complete("s", "prosa por favor")
    assert "response_format" not in captured["payload"]


def test_azure_half_configured_is_not_usable(monkeypatch):
    # Azure sem api_version não é utilizável → o gate não deve aprová-lo
    # (build() só devolve provedores available()).
    monkeypatch.setenv("EIGAN_AI_PROVIDER", "azure")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "meu-deploy")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com")
    monkeypatch.delenv("AZURE_OPENAI_API_VERSION", raising=False)
    assert default_provider() is None  # falta api_version → inutilizável
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
    assert default_provider() is not None  # agora completo


def test_register_new_provider_without_touching_core():
    # adicionar provedor = registrar um ProviderSpec (interface padrão), sem
    # alterar o resto do código — exatamente o requisito de modularidade.
    register(
        ProviderSpec(
            "meu_provedor",
            "Provedor Custom",
            OpenAIProvider,
            "MEUPROV_API_KEY",
            "MEUPROV_MODEL",
            base_url_env="MEUPROV_BASE_URL",
            default_base_url="https://exemplo/v1",
        )
    )
    assert any(s.name == "meu_provedor" for s in list_providers())


# --------------------------------------------------------------------------- #
# Round-trip Anthropic (MockTransport) + redaction no envio
# --------------------------------------------------------------------------- #
def test_anthropic_roundtrip_and_grounding():
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "EXPLICAÇÃO: risco alto\nREMEDIAÇÃO: filtre"}]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnthropicProvider(model="claude-opus-4-8", credential="sk-test", client=client)
    exp = provider.explain(_finding(), "contexto")
    assert exp.ai_generated is True
    assert "risco alto" in exp.text and "filtre" in exp.remediation
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "sk-test"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert captured["body"]["model"] == "claude-opus-4-8"


def test_anthropic_marks_system_prompt_cacheable():
    # Prompt caching (§2.2): o system (prefixo estável) vai como bloco com
    # cache_control ephemeral — corta o custo dos tokens repetidos entre ondas.
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnthropicProvider(model="claude-opus-4-8", credential="k", client=client)
    provider.complete("SYSTEM ESTAVEL", "user variavel")
    system = captured["body"]["system"]
    assert isinstance(system, list)
    assert system[0]["text"] == "SYSTEM ESTAVEL"
    assert system[0]["cache_control"] == {"type": "ephemeral"}


def test_external_provider_redacts_before_send():
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnthropicProvider(model="claude-opus-4-8", credential="k", client=client)
    finding = _finding()
    finding.description = "senha encontrada password: s3cr3t no log"
    provider.explain(finding, "")
    sent = captured["body"]["messages"][0]["content"]
    assert "s3cr3t" not in sent and "[REDACTED]" in sent


# --------------------------------------------------------------------------- #
# Fallback determinístico intacto
# --------------------------------------------------------------------------- #
class _Boom(AIProvider):
    def available(self) -> bool:
        return True

    def explain(self, finding, context) -> Explanation:
        raise RuntimeError("sem rede")


def test_enricher_falls_back_when_provider_errors(tmp_path):
    enricher = Enricher(KnowledgeBase(tmp_path), provider=_Boom())
    exp = enricher.explain(_finding())
    assert exp.ai_generated is False  # caiu para o determinístico, sem quebrar
    assert exp.text


def test_enricher_without_provider_is_deterministic(tmp_path):
    enricher = Enricher(KnowledgeBase(tmp_path), provider=None)
    assert enricher.ai_enabled is False
    assert enricher.explain(_finding()).ai_generated is False


# --------------------------------------------------------------------------- #
# Ollama local (round-trip, normalização de host, timeout) — antes sem cobertura
# --------------------------------------------------------------------------- #
def test_ollama_roundtrip_and_host_normalization():
    # Prova o parser Ollama (/api/chat → message.content) E que um OLLAMA_HOST sem
    # esquema ('localhost:11434') vira uma URL válida (http://…), que antes quebrava.
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"message": {"content": "resposta local"}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = OllamaProvider(model="qwen2.5:0.5b", credential="localhost:11434", client=client)
    assert provider.complete("s", "u") == "resposta local"
    assert captured["url"] == "http://localhost:11434/api/chat"


def _ollama_client(models):
    httpx = pytest.importorskip("httpx")

    def handler(request):
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"model": m} for m in models]})
        return httpx.Response(200, json={"message": {"content": "x"}})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ollama_probe_ok_when_model_present():
    client = _ollama_client(["qwen2.5:0.5b", "llama3.2:1b"])
    p = OllamaProvider(model="qwen2.5:0.5b", credential="http://localhost:11434", client=client)
    ok, detail = p.probe()
    assert ok and "presente" in detail


def test_ollama_probe_matches_by_base_name():
    # usuário setou só 'qwen2.5' (sem :tag) — casa pelo nome base
    client = _ollama_client(["qwen2.5:0.5b"])
    ok, _ = OllamaProvider(model="qwen2.5", credential="http://h", client=client).probe()
    assert ok


def test_ollama_probe_fails_when_model_not_pulled():
    client = _ollama_client(["outro-modelo"])
    ok, detail = OllamaProvider(model="qwen2.5:0.5b", credential="http://h", client=client).probe()
    assert not ok and "pull" in detail  # aponta o comando exato


def test_ollama_probe_fails_when_server_down():
    httpx = pytest.importorskip("httpx")

    def handler(request):
        raise httpx.ConnectError("connection refused")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ok, detail = OllamaProvider(
        model="m", credential="http://localhost:11434", client=client
    ).probe()
    assert not ok and "não respondeu" in detail


def test_cloud_probe_ok_and_failure():
    httpx = pytest.importorskip("httpx")

    def ok_handler(request):
        return httpx.Response(200, json={"content": [{"type": "text", "text": "pong"}]})

    p = AnthropicProvider(
        model="claude-opus-4-8",
        credential="k",
        client=httpx.Client(transport=httpx.MockTransport(ok_handler)),
    )
    ok, detail = p.probe()
    assert ok and "pong" in detail

    def boom_handler(request):
        return httpx.Response(500, json={"error": "x"})

    p2 = AnthropicProvider(
        model="m", credential="k", client=httpx.Client(transport=httpx.MockTransport(boom_handler))
    )
    ok2, _ = p2.probe()
    assert not ok2  # HTTP 500 → raise_for_status → probe reporta falha (não crash)


def test_ollama_uses_local_timeout(monkeypatch):
    # A regressão real: timeout curto fazia toda completude local estourar.
    assert PROVIDERS["ollama"].timeout == _LOCAL_TIMEOUT
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "m")
    prov = PROVIDERS["ollama"].build()
    assert prov is not None and prov._timeout == _LOCAL_TIMEOUT  # 300s, não os 60s da nuvem


def test_ai_timeout_env_override(monkeypatch):
    monkeypatch.setenv("EIGAN_AI_TIMEOUT", "12.5")
    monkeypatch.setenv("OLLAMA_HOST", "http://h")
    monkeypatch.setenv("OLLAMA_MODEL", "m")
    assert PROVIDERS["ollama"].build()._timeout == 12.5
