"""Cache de resposta de IA por conteúdo (§2.3): dedup, persistência, redaction."""

from __future__ import annotations

import pytest

from eigan.ai.cache import ResponseCache
from eigan.ai.provider import AnthropicProvider
from eigan.findings.schema import Finding, Severity


def test_cache_key_stability_and_invalidation() -> None:
    c = ResponseCache()
    k = c.key(system="S", user="U", model="m")
    assert c.key(system="S", user="U", model="m") == k  # estável
    assert c.key(system="S", user="U", model="OUTRO") != k  # modelo muda → miss
    assert c.key(system="S2", user="U", model="m") != k  # prompt muda → miss
    assert c.key(system="S", user="U", model="m", json_mode=True) != k  # modo muda → miss
    assert ResponseCache(version="2").key(system="S", user="U", model="m") != k  # versão muda


def test_cache_normalizes_whitespace() -> None:
    c = ResponseCache()
    assert c.key(system="a  b", user="U", model="m") == c.key(system="a b ", user="U", model="m")


def test_cache_get_put_and_persistence(tmp_path) -> None:
    path = tmp_path / "cache.json"
    c = ResponseCache(path=path)
    assert c.get("k") is None
    c.put("k", "resposta")
    assert c.get("k") == "resposta"
    # Persistiu em disco: nova instância no mesmo path recupera (economia entre scans).
    assert ResponseCache(path=path).get("k") == "resposta"


def _finding() -> Finding:
    return Finding(
        title="XSS", severity=Severity.HIGH, affected_asset="http://x/a", source_tool="t"
    )


def test_provider_explain_uses_cache() -> None:
    # 2ª análise idêntica (finding, contexto, modelo) → cache hit, sem 2ª chamada.
    httpx = pytest.importorskip("httpx")
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(
            200, json={"content": [{"type": "text", "text": "EXPLICAÇÃO: x\nREMEDIAÇÃO: y"}]}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnthropicProvider(
        model="claude-opus-4-8", credential="k", client=client, cache=ResponseCache()
    )
    e1 = provider.explain(_finding(), "contexto")
    e2 = provider.explain(_finding(), "contexto")
    assert calls["n"] == 1  # a 2ª não pagou a chamada
    assert e1.text == e2.text


def test_provider_cache_stores_redacted_value() -> None:
    # P8: o valor guardado é a resposta JÁ redigida (externo) — segredo nunca em claro.
    httpx = pytest.importorskip("httpx")

    def handler(request):
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "EXPLICAÇÃO: token=abcd1234secret\nREMEDIAÇÃO: y"}
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = ResponseCache()
    provider = AnthropicProvider(model="m", credential="k", client=client, cache=cache)
    provider.explain(_finding(), "contexto")
    stored = "".join(cache._mem.values())
    assert "abcd1234secret" not in stored  # redigido antes de gravar
    assert "[REDACTED]" in stored
