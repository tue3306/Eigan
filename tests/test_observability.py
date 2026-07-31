"""Testes da observabilidade de tokens/custo (§22, ADR-0025).

Cobrem: normalização dos 4 formatos oficiais de uso, agregação thread-safe,
escopo por execução (contextvar), gravação a partir de um provedor real (via
MockTransport) e a regra de veracidade do custo (UNVERIFIED sem preço confirmado).
"""

from __future__ import annotations

import threading

import pytest

from eigan.observability.cost import CostModel
from eigan.observability.usage import (
    TokenUsage,
    UsageEvent,
    UsageMeter,
    current_meter,
    extract_usage,
    record_completion,
    use_meter,
)


# --------------------------------------------------------------------------- #
# extract_usage — os 4 formatos oficiais + desconhecido
# --------------------------------------------------------------------------- #
def test_extract_usage_openai_shape():
    u = extract_usage({"usage": {"prompt_tokens": 12, "completion_tokens": 34}})
    assert u == TokenUsage(12, 34)
    assert u.total_tokens == 46


def test_extract_usage_anthropic_shape():
    assert extract_usage({"usage": {"input_tokens": 5, "output_tokens": 7}}) == TokenUsage(5, 7)


def test_extract_usage_gemini_shape():
    raw = {"usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 20}}
    assert extract_usage(raw) == TokenUsage(100, 20)


def test_extract_usage_ollama_shape():
    assert extract_usage({"prompt_eval_count": 8, "eval_count": 9}) == TokenUsage(8, 9)


def test_extract_usage_openai_cached_tokens():
    # OpenAI: prompt_tokens já é o total; cached_tokens é o subconjunto do cache (§2.2).
    u = extract_usage(
        {
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 10,
                "prompt_tokens_details": {"cached_tokens": 80},
            }
        }
    )
    assert u == TokenUsage(100, 10, cache_read_tokens=80)
    assert u is not None and u.total_tokens == 110  # cache é subconjunto do prompt


def test_extract_usage_anthropic_prompt_cache():
    # Anthropic: input_tokens é a parte NÃO cacheada; leitura/criação vêm à parte (§2.2).
    u = extract_usage(
        {
            "usage": {
                "input_tokens": 20,
                "output_tokens": 8,
                "cache_read_input_tokens": 200,
                "cache_creation_input_tokens": 50,
            }
        }
    )
    # prompt_tokens normaliza para o total de entrada (20+200+50); cache_read = 200.
    assert u == TokenUsage(270, 8, cache_read_tokens=200)


def test_extract_usage_returns_none_when_unknown():
    # Sem bloco de uso conhecido → None. NUNCA inventa um número (§2/§3.1).
    assert extract_usage({"choices": [{"message": {"content": "x"}}]}) is None
    assert extract_usage("não é dict") is None
    assert extract_usage({"usage": {"input_tokens": True}}) == TokenUsage(0, 0)  # bool não conta


# --------------------------------------------------------------------------- #
# TokenUsage
# --------------------------------------------------------------------------- #
def test_token_usage_add_and_dict():
    total = TokenUsage(1, 2, 1) + TokenUsage(10, 20, 4)
    assert total == TokenUsage(11, 22, 5)
    assert total.as_dict() == {
        "prompt_tokens": 11,
        "completion_tokens": 22,
        "total_tokens": 33,
        "cache_read_tokens": 5,
    }


# --------------------------------------------------------------------------- #
# UsageMeter
# --------------------------------------------------------------------------- #
def test_meter_aggregates_total_and_by_model():
    meter = UsageMeter()
    meter.record(UsageEvent("openai", "gpt-5", TokenUsage(10, 5)))
    meter.record(UsageEvent("openai", "gpt-5", TokenUsage(2, 3)))
    meter.record(UsageEvent("anthropic", "claude", TokenUsage(1, 1)))
    assert meter.call_count() == 3
    assert meter.total() == TokenUsage(13, 9)
    assert meter.by_model() == {
        "openai:gpt-5": TokenUsage(12, 8),
        "anthropic:claude": TokenUsage(1, 1),
    }
    meter.reset()
    assert meter.call_count() == 0


def test_meter_is_thread_safe():
    meter = UsageMeter()

    def worker() -> None:
        for _ in range(200):
            meter.record(UsageEvent("p", "m", TokenUsage(1, 1)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert meter.call_count() == 8 * 200
    assert meter.total() == TokenUsage(1600, 1600)


def test_use_meter_scopes_the_current_meter():
    scoped = UsageMeter()
    assert current_meter() is not scoped
    with use_meter(scoped) as m:
        assert current_meter() is scoped is m
        record_completion(
            "openai", "gpt-5", {"usage": {"prompt_tokens": 4, "completion_tokens": 6}}
        )
    assert scoped.total() == TokenUsage(4, 6)
    # fora do bloco, o medidor volta ao global (o escopado não recebe mais nada)
    assert current_meter() is not scoped


def test_record_completion_returns_none_without_usage():
    with use_meter(UsageMeter()) as m:
        assert record_completion("x", "m", {"no": "usage"}) is None
        assert m.call_count() == 0


# --------------------------------------------------------------------------- #
# CostModel — veracidade: sem preço verificado, custo é UNVERIFIED (None)
# --------------------------------------------------------------------------- #
def test_cost_is_none_when_model_absent():
    assert CostModel({}).cost_for("gpt-5", TokenUsage(1000, 1000)) is None


def test_cost_is_none_when_not_verified():
    prices = {"gpt-5": {"input_per_1k": 1.0, "output_per_1k": 2.0, "verified": False}}
    assert CostModel(prices).cost_for("gpt-5", TokenUsage(1000, 1000)) is None


def test_cost_computed_when_verified():
    prices = {
        "gpt-5": {
            "input_per_1k": 0.5,
            "output_per_1k": 1.5,
            "currency": "USD",
            "source": "https://exemplo/pricing",
            "verified": True,
        }
    }
    est = CostModel(prices).cost_for("gpt-5", TokenUsage(2000, 1000))
    assert est is not None
    assert est.amount == pytest.approx(2000 / 1000 * 0.5 + 1000 / 1000 * 1.5)  # 1.0 + 1.5 = 2.5
    assert est.currency == "USD" and est.verified is True
    assert est.source == "https://exemplo/pricing"


def test_cost_none_when_price_malformed():
    prices = {"m": {"input_per_1k": "grátis", "output_per_1k": 1.0, "verified": True}}
    assert CostModel(prices).cost_for("m", TokenUsage(10, 10)) is None


def test_cost_model_from_missing_config_is_empty(tmp_path):
    model = CostModel.from_config(tmp_path / "não-existe.yaml")
    assert model.cost_for("qualquer", TokenUsage(1, 1)) is None


def test_shipped_pricing_config_has_no_fabricated_prices():
    # O arquivo versionado NÃO pode conter preço real (models: {}). Garante que não
    # entregamos um preço inventado que viraria "custo" falso.
    model = CostModel.from_config()
    assert model.cost_for("gpt-5", TokenUsage(1000, 1000)) is None


# --------------------------------------------------------------------------- #
# Integração: um provedor real grava uso no medidor corrente (via MockTransport)
# --------------------------------------------------------------------------- #
def test_provider_records_usage_into_current_meter():
    httpx = pytest.importorskip("httpx")
    from eigan.ai.provider import AnthropicProvider

    def handler(request):
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 42, "output_tokens": 8},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnthropicProvider(model="claude-opus-4-8", credential="k", client=client)
    meter = UsageMeter()
    with use_meter(meter):
        assert provider.complete("s", "u") == "ok"
    assert meter.total() == TokenUsage(42, 8)
    assert meter.by_model() == {"anthropic:claude-opus-4-8": TokenUsage(42, 8)}


# --------------------------------------------------------------------------- #
# Persistência do uso de tokens no scan (round-trip no FindingStore)
# --------------------------------------------------------------------------- #
def test_store_persists_and_reads_token_usage(tmp_path):
    from eigan.findings.store import FindingStore

    store = FindingStore(str(tmp_path / "obs.db"))
    sid = store.create_scan("eng", "external/standard", ["example.com"])
    assert store.get_token_usage(sid) is None  # sem IA ainda → None (não zero fabricado)
    payload = {
        "total": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15, "calls": 2},
        "by_model": {
            "openai:gpt-5": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        },
    }
    store.set_token_usage(sid, payload)
    assert store.get_token_usage(sid) == payload
    store.close()
