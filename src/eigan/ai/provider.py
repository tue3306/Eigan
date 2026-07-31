"""Camada de IA — provedor multi-fornecedor (AI-native, ADR-0012).

EIGAN é um agente de IA: sem um provedor configurado, o scan é recusado
(:func:`require_provider`). Registro modular (:class:`ProviderSpec`) para
Anthropic/OpenAI/Gemini/OpenRouter/Groq/Together/Azure + **Ollama local**.

Os mecanismos determinísticos (skills/`DeterministicEnricher`, cascata) são o
**substrato** que a IA comanda — não um "modo sem IA". A IA nunca afirma
CVE/versão fora das evidências (grounding); toda saída é marcada
``ai_generated=True``; **redaction** de segredos/PII antes de provedor externo.
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..findings.schema import Finding, Severity
from ..knowledge.loader import KnowledgeBase
from .cache import ResponseCache


@dataclass
class Explanation:
    text: str
    remediation: str
    ai_generated: bool


class AIProvider(ABC):
    """Porta multi-provedor. Implementações concretas (Anthropic/OpenAI/Google/
    Ollama) vivem na infra e são plugadas via config/ai.yaml + env."""

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def explain(self, finding: Finding, context: str) -> Explanation: ...

    def probe(self) -> tuple[bool, str]:
        """Checagem **real** de reachability: diferente de :meth:`available`
        (que só olha a config), faz uma chamada mínima e diz se a IA de fato
        respondeu. Sobrescrita pelos provedores concretos; nunca levanta."""
        return False, "provedor não suporta verificação de reachability"


class DeterministicEnricher:
    """Substrato de enriquecimento (resiliência intra-scan + relatório determinístico):
    monta explicação e remediação a partir da base de conhecimento (skills) casada por
    CWE/OWASP. **Não** é um "modo sem IA" de produto — o scan exige um provedor
    (ADR-0012); isto cobre a falha/ausência de IA numa etapa e o caminho determinístico
    do relatório (exporters/KB)."""

    def __init__(self, kb: KnowledgeBase) -> None:
        self._kb = kb

    def explain(self, finding: Finding) -> Explanation:
        skill = self._kb.match(cwe=finding.cwe, owasp=finding.owasp)
        if skill:
            explanation = skill.section("When to Use") or skill.description
            remediation = skill.section("Remediation") or "Consulte as referências do finding."
            body = (
                f"{finding.description}\n\n{explanation}".strip()
                if finding.description
                else explanation
            )
            return Explanation(text=body, remediation=remediation, ai_generated=False)

        # sem skill correspondente: texto determinístico genérico a partir dos campos
        text = finding.description or (
            f"Finding '{finding.title}' de severidade {finding.severity.value} "
            f"no ativo {finding.affected_asset}, reportado por {finding.source_tool}."
        )
        remediation = (
            "Sem playbook específico na base de conhecimento. "
            "Revise as referências e aplique o princípio do menor privilégio."
        )
        return Explanation(text=text, remediation=remediation, ai_generated=False)


def _class_key(finding: Finding) -> str:
    """Chave de CLASSE de vulnerabilidade — ignora o ativo, para a dedup semântica
    antes da IA (§2.4). Prefere CWE > OWASP > título normalizado."""
    if finding.cwe:
        return f"cwe:{finding.cwe}"
    if finding.owasp:
        return f"owasp:{finding.owasp}"
    return f"title:{finding.title.strip().lower()}"


def _triage_min_severity() -> Severity:
    """Severidade mínima para análise PROFUNDA por IA (§2.5). Abaixo dela, a triagem
    barata usa o enriquecimento determinístico (zero token). Default ``low`` (só INFO
    fica breve); ``info`` manda tudo ao modelo caro; ``high`` é a economia agressiva.

    Teto de segurança: o limiar NUNCA sobe acima de HIGH — findings de severidade
    alta/crítica sempre vão a análise profunda (nunca desprioriza em silêncio, §P9)."""
    raw = (os.getenv("EIGAN_TRIAGE_MIN_SEVERITY") or "low").strip().lower()
    try:
        sev = Severity(raw)
    except ValueError:
        sev = Severity.LOW
    return sev if sev.rank <= Severity.HIGH.rank else Severity.HIGH


class Enricher:
    """Fachada: usa IA se disponível, senão cai para o determinístico.

    Nunca falha por ausência de chave — degrada graciosamente.
    """

    def __init__(self, kb: KnowledgeBase, provider: AIProvider | None = None) -> None:
        self._fallback = DeterministicEnricher(kb)
        self._kb = kb
        self._provider = provider if (provider and provider.available()) else None

    @property
    def ai_enabled(self) -> bool:
        return self._provider is not None

    def explain(self, finding: Finding) -> Explanation:
        if self._provider is None:
            return self._fallback.explain(finding)
        # grounding: entrega apenas a skill relevante como contexto
        skill = self._kb.match(cwe=finding.cwe, owasp=finding.owasp)
        context = (skill.section("Remediation") if skill else "") or finding.description
        try:
            return self._provider.explain(finding, context)
        except Exception:  # noqa: BLE001 — qualquer falha de IA cai para determinístico
            return self._fallback.explain(finding)

    def explain_all(self, findings: list[Finding]) -> list[Explanation]:
        """Dedup semântica (§2.4) + triagem barata→cara (§2.5), mantendo a ordem.

        Agrupa por CLASSE (§2.4) e, por grupo, a triagem decide **DEEP** (narrativa por
        IA, cara) ou **BRIEF** (enriquecimento determinístico, barato) pela severidade
        MÁXIMA do grupo vs. :func:`_triage_min_severity`. O custo cresce com o número de
        classes RELEVANTES, não de instâncias. Regras de segurança (§P9): nada é
        descartado — BRIEF ainda recebe explicação; alto/crítico SEMPRE vai a DEEP; a
        escolha é auditável (``Explanation.ai_generated`` indica se a IA foi usada)."""
        groups: dict[str, list[Finding]] = {}
        order: list[str] = []
        for finding in findings:
            key = _class_key(finding)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(finding)

        min_rank = _triage_min_severity().rank
        by_class: dict[str, Explanation] = {}
        for key in order:
            group = groups[key]
            deep = self._provider is not None and max(f.severity.rank for f in group) >= min_rank
            # DEEP: narrativa por IA (self.explain). BRIEF: determinístico (barato).
            by_class[key] = self.explain(group[0]) if deep else self._fallback.explain(group[0])
        return [by_class[_class_key(f)] for f in findings]


# --------------------------------------------------------------------------- #
# Adapters concretos multi-provedor (via httpx, dependência do extra [ai]).
#
# Grounding (§7): só enviamos as evidências do finding + a skill relevante como
# contexto — nunca pedimos ao modelo para inventar CVE/versão. Redaction remove
# segredos/PII antes de sair para provedor EXTERNO (Ollama é local → sem
# redaction). Toda saída é marcada ai_generated=True. Qualquer falha de rede/
# parse propaga e o Enricher cai para o determinístico (fallback intacto).
#
# Model id da Anthropic verificado (claude-api skill); demais provedores exigem
# <PROVIDER>_MODEL no ambiente — anti-invenção (§3.1): não fixamos um id que não
# confirmamos. Chaves só por variável de ambiente, nunca em arquivo (§5).
# --------------------------------------------------------------------------- #
_DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"  # verificado (claude-api skill)
_ANTHROPIC_VERSION = "2023-06-01"
# Orçamento de saída generoso: modelos de raciocínio (GPT-5, o-series) gastam
# tokens "pensando" que contam contra este teto — com pouco, retornariam vazio e
# a IA pareceria "configurada mas não funciona" (foi um bug real: 2048 era
# integralmente consumido pelo raciocínio do GPT-5 em tarefas de geração rica —
# remediação/análise — devolvendo conteúdo vazio). 4096 + `reasoning_effort` baixo
# (ver `_openai_reasoning_effort`) cobrem raciocínio + narrativa com folga.
# Ajustável por env EIGAN_AI_MAX_TOKENS.
_MAX_TOKENS = 4096
_TIMEOUT = 60.0  # provedores de nuvem (rede)


def _max_tokens() -> int:
    raw = os.getenv("EIGAN_AI_MAX_TOKENS")
    if raw:
        try:
            return max(256, int(raw))
        except ValueError:
            pass
    return _MAX_TOKENS


# Modelos de raciocínio da OpenAI aceitam `reasoning_effort` (minimal|low|medium|
# high). Sem ele, o GPT-5 usa esforço "medium" por padrão e pode gastar TODO o
# `max_completion_tokens` só raciocinando → conteúdo vazio. Verificado ao vivo:
# `low` corta o raciocínio (192 tok) e devolve a saída completa em ~10s (vs. 22s
# e VAZIO no default). Só se aplica a modelos de raciocínio (gpt-5*, o1/o3/o4*).
_OPENAI_REASONING_PREFIXES = ("gpt-5", "o1", "o3", "o4")


def _openai_reasoning_effort(model: str) -> str | None:
    """`reasoning_effort` a enviar para ``model`` (ou None se não se aplica).

    Default ``low`` (bom equilíbrio custo/qualidade em geração estruturada);
    ajustável por env ``EIGAN_OPENAI_REASONING_EFFORT`` (``none`` desliga)."""
    m = (model or "").strip().lower()
    if not any(m.startswith(p) for p in _OPENAI_REASONING_PREFIXES):
        return None
    eff = (os.getenv("EIGAN_OPENAI_REASONING_EFFORT") or "low").strip().lower()
    if eff in ("none", "off", ""):
        return None
    return eff if eff in ("minimal", "low", "medium", "high") else "low"


# ── Tiers de qualidade (baixo/médio/alto) ──────────────────────────────────── #
# O usuário escolhe o NÍVEL, não o id do modelo — o EIGAN resolve o modelo concreto
# por provedor (mapa abaixo + config/ai.yaml). Um id explícito em <PROVIDER>_MODEL
# ainda vence (override de power-user). Só Anthropic e OpenAI têm defaults que
# conseguimos verificar; os demais ficam marcados p/ VERIFICAR na config.
TIERS = ("low", "medium", "high")
_DEFAULT_TIER = "medium"
_TIER_LABELS = {
    "low": "Baixo — rápido e econômico",
    "medium": "Médio — equilíbrio (recomendado)",
    "high": "Alto — máxima capacidade de raciocínio",
}


def current_tier() -> str:
    """Nível de qualidade escolhido (env ``EIGAN_AI_TIER``), default 'medium'."""
    t = (os.getenv("EIGAN_AI_TIER") or _DEFAULT_TIER).strip().lower()
    return t if t in TIERS else _DEFAULT_TIER


# Modelo local (Ollama) na CPU carrega o modelo + gera devagar: um timeout curto
# faz CADA completude real estourar e cair no determinístico ("configurado mas não
# funciona"). Medido: um round-trip trivial num modelo 0.5B pode passar de 20s.
# Ajustável por env ``EIGAN_AI_TIMEOUT`` (segundos).
_LOCAL_TIMEOUT = 300.0

_SYSTEM_PROMPT = (
    "Você é um analista de segurança sênior. Explique o finding para uma equipe "
    "técnica e proponha remediação acionável. Use SOMENTE as evidências fornecidas; "
    "NUNCA invente CVE, versão, score ou fato que não esteja nas evidências. Responda "
    "em português, em duas seções rotuladas exatamente 'EXPLICAÇÃO:' e 'REMEDIAÇÃO:'."
)

_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|authorization|bearer)\b\s*[:=]\s*\S+"
    ),
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),  # e-mail (PII)
]


def redact(text: str) -> str:
    """Remove segredos/PII antes de enviar a um provedor EXTERNO (§7)."""
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def _ai_cache_path() -> str | None:
    """Cache de resposta persistente (§2.3) se ``EIGAN_AI_CACHE_DIR`` estiver
    definido; senão None (cache só em memória, dentro do scan)."""
    d = os.getenv("EIGAN_AI_CACHE_DIR")
    return str(Path(d) / "ai_response_cache.json") if d else None


def _build_prompts(finding: Finding, context: str) -> tuple[str, str]:
    lines = [
        f"Título: {finding.title}",
        f"Severidade: {finding.severity.value}",
        f"Ativo afetado: {finding.affected_asset}",
        f"Ferramenta de origem: {finding.source_tool}",
    ]
    if finding.cwe:
        lines.append(f"CWE: {finding.cwe}")
    if finding.owasp:
        lines.append(f"OWASP: {finding.owasp}")
    if finding.description:
        lines.append(f"Descrição: {finding.description}")
    if context:
        lines.append(f"\nContexto (base de conhecimento, para fundamentar):\n{context}")
    return _SYSTEM_PROMPT, "Evidências do finding:\n" + "\n".join(lines)


def _parse_explanation(raw: str, finding: Finding) -> Explanation:
    text = raw.strip()
    remediation = ""
    upper = text.upper()
    if "REMEDIAÇÃO:" in upper:
        idx = upper.index("REMEDIAÇÃO:")
        remediation = text[idx + len("REMEDIAÇÃO:") :].strip()
        text = text[:idx]
    text = re.sub(r"(?i)^\s*EXPLICAÇÃO:\s*", "", text).strip()
    if not remediation:
        remediation = "Consulte as referências do finding e aplique o menor privilégio."
    return Explanation(text=text or finding.description, remediation=remediation, ai_generated=True)


class _HTTPProvider(AIProvider):
    """Base dos provedores HTTP: constrói o prompt (grounded), redige externos,
    delega a chamada a ``_complete`` e normaliza para :class:`Explanation`."""

    def __init__(
        self,
        *,
        model: str,
        credential: str,
        redact_external: bool = True,
        timeout: float = _TIMEOUT,
        client: Any = None,
        cache: ResponseCache | None = None,
    ) -> None:
        self._model = model
        self._credential = credential
        self._redact_external = redact_external
        self._timeout = timeout
        self._client = client  # injetável para teste (httpx.Client com MockTransport)
        # Cache de resposta por conteúdo (§2.3): None = sem cache. Reduz dupla análise
        # do mesmo (finding, contexto, modelo) na mesma execução (e entre scans se
        # persistente). Só o `explain` o usa (o Planner tem retry, não cacheado).
        self._cache = cache

    def available(self) -> bool:
        return bool(self._credential and self._model)

    def explain(self, finding: Finding, context: str) -> Explanation:
        system, user = _build_prompts(finding, context)
        if self._redact_external:
            user = redact(user)
        return _parse_explanation(self._cached_complete(system, user), finding)

    def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        """Completamento de texto genérico — porta para o Planner cognitivo
        (ADR-0007). Aplica a mesma redaction externa que ``explain`` (o prompt do
        Planner pode conter títulos/ativos de findings).

        ``json_mode`` pede ao provedor a **saída estruturada** (JSON garantido
        sintaticamente) onde suportado — sem ele, modelos como o GPT-5 às vezes
        emitem JSON malformado (aspa faltando) e o Planner caía no determinístico."""
        redacted = redact(user) if self._redact_external else user
        return self._complete(system, redacted, json_mode=json_mode)

    def _cached_complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        """Cache de resposta (§2.3) para a análise de finding (``explain``). O Planner
        (``complete``) NÃO é cacheado: seu retry depende de o modelo poder devolver
        uma saída diferente/válida na 2ª tentativa. ``user`` já vem redigido; grava a
        resposta **já redigida** (P8) — a chave é hash, o prompt não vai em claro."""
        cache = self._cache
        if cache is None:
            return self._complete(system, user, json_mode=json_mode)
        key = cache.key(system=system, user=user, model=self._model, json_mode=json_mode)
        hit = cache.get(key)
        if hit is not None:
            return hit
        out = self._complete(system, user, json_mode=json_mode)
        cache.put(key, redact(out) if self._redact_external else out)
        return out

    def probe(self) -> tuple[bool, str]:
        """Faz uma completude mínima real para provar que a IA responde (custa
        poucos tokens na nuvem; Ollama sobrescreve com uma checagem sem inferência)."""
        try:
            out = self._complete("Responda apenas: pong", "ping")
        except Exception as exc:  # noqa: BLE001 — o objetivo é reportar a falha
            return False, f"{type(exc).__name__}: {exc}"
        text = (out or "").strip().replace("\n", " ")
        return (bool(text), text[:80] if text else "resposta vazia do provedor")

    def _complete(  # pragma: no cover - abstrato
        self, system: str, user: str, *, json_mode: bool = False
    ) -> str:
        raise NotImplementedError

    def _post(self, url: str, *, headers: dict[str, str], payload: dict) -> dict:
        import httpx  # import tardio: só quando a IA é usada de fato (extra [ai])

        if self._client is not None:
            resp = self._client.post(url, headers=headers, json=payload)
        else:
            resp = httpx.post(url, headers=headers, json=payload, timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()
        self._meter_usage(data)
        return data

    def _meter_usage(self, data: object) -> None:
        """Registra o uso de tokens desta chamada (observabilidade §22, ADR-0025).

        Best-effort: a telemetria **nunca** derruba a chamada de IA. O nome do
        provedor é derivado da classe (``AnthropicProvider`` → ``anthropic``)."""
        try:
            from ..observability.usage import record_completion

            name = type(self).__name__.removesuffix("Provider").lower() or "ai"
            record_completion(name, self._model, data)
        except Exception:  # noqa: BLE001 — telemetria é best-effort
            pass


class AnthropicProvider(_HTTPProvider):
    def _complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        # Anthropic não tem um flag "json_object"; o grounding por prompt já pede
        # JSON e o modelo cumpre bem. json_mode é aceito para uniformizar a porta.
        data = self._post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self._credential,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            payload={
                "model": self._model,
                "max_tokens": _max_tokens(),
                # Prompt caching (§2.2): o system prompt é o prefixo ESTÁVEL (regras de
                # grounding, catálogo de capacidades) reenviado a cada onda — marcá-lo
                # como cacheável (ephemeral) corta o custo dos tokens repetidos. Prompt
                # abaixo do mínimo do provedor simplesmente não é cacheado (sem erro).
                # Só a Anthropic recebe o marcador aqui; a porta CompletionPort segue
                # genérica (os demais provedores ignoram / cacheiam prefixo sozinhos).
                "system": [
                    {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
                ],
                "messages": [{"role": "user", "content": user}],
            },
        )
        for block in data.get("content", []):
            if block.get("type") == "text":
                return str(block.get("text", ""))
        return ""


class _OpenAICompatProvider(_HTTPProvider):
    """Base para provedores que falam o schema **OpenAI Chat Completions**.

    A maioria dos provedores modernos é compatível com a OpenAI: muda só a
    ``base_url`` e o header de auth. Assim, adicionar OpenRouter/Groq/Together é
    só declarar a URL — sem reescrever a lógica (o pedido de modularidade do
    §AI Providers). A ``base_url`` é **sobrescritível por env** para não fixarmos
    um endpoint que possa mudar (anti-invenção §3.1)."""

    default_base_url = "https://api.openai.com/v1"
    # Nome do parâmetro de limite de saída. Os modelos novos da OpenAI (GPT-5/
    # o-series) recusam ``max_tokens`` e exigem ``max_completion_tokens``; gateways
    # OpenAI-compat mais antigos (Groq/Together) ainda usam ``max_tokens``. Por isso
    # é um atributo sobrescrevível por subclasse (verificado contra a API real).
    token_param = "max_tokens"

    def __init__(self, *, base_url: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._base_url = (base_url or self.default_base_url).rstrip("/")

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._credential}",
            "content-type": "application/json",
        }

    def _complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        payload: dict[str, Any] = {
            "model": self._model,
            self.token_param: _max_tokens(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        # Saída estruturada: força JSON sintaticamente válido (a mensagem já contém
        # a palavra "JSON", exigência da API). Elimina o JSON malformado do GPT-5.
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        payload.update(self._extra_payload())
        data = self._post(
            f"{self._base_url}/chat/completions",
            headers=self._auth_headers(),
            payload=payload,
        )
        msg = data["choices"][0].get("message", {})
        return str(msg.get("content") or "")

    def _extra_payload(self) -> dict[str, Any]:
        """Campos extras específicos do provedor (hook). Base: nenhum."""
        return {}


class OpenAIProvider(_OpenAICompatProvider):
    default_base_url = "https://api.openai.com/v1"
    # A API nativa da OpenAI (gpt-4o em diante e toda a série GPT-5) usa
    # ``max_completion_tokens``; ``max_tokens`` retorna HTTP 400 nos modelos novos.
    token_param = "max_completion_tokens"

    def _extra_payload(self) -> dict[str, Any]:
        # Modelos de raciocínio (GPT-5, o-series): envia `reasoning_effort` baixo
        # para não gastar todo o orçamento raciocinando e devolver vazio (§3.4).
        eff = _openai_reasoning_effort(self._model)
        return {"reasoning_effort": eff} if eff else {}


class OpenRouterProvider(_OpenAICompatProvider):
    # Confirmado na doc oficial (openrouter.ai/docs/quickstart): OpenAI-compat.
    default_base_url = "https://openrouter.ai/api/v1"


class GroqProvider(_OpenAICompatProvider):
    # Confirmado (console.groq.com/docs/openai): base OpenAI-compat.
    default_base_url = "https://api.groq.com/openai/v1"


class TogetherProvider(_OpenAICompatProvider):
    # Confirmado (docs.together.ai/docs/openai-api-compatibility).
    default_base_url = "https://api.together.xyz/v1"


class AzureOpenAIProvider(_HTTPProvider):
    """Azure OpenAI: endpoint por *resource*/*deployment* + ``api-version``.

    Difere do OpenAI padrão: auth por header ``api-key``, o "modelo" é o nome do
    **deployment**, e a URL exige a ``api-version`` (que muda — vem por env, nunca
    fixada; §3.1). Requer ``AZURE_OPENAI_ENDPOINT`` e ``AZURE_OPENAI_API_VERSION``.
    """

    def __init__(self, *, base_url: str, api_version: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._endpoint = base_url.rstrip("/")
        self._api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "")

    def available(self) -> bool:
        return bool(self._credential and self._model and self._endpoint and self._api_version)

    def _complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        url = (
            f"{self._endpoint}/openai/deployments/{self._model}"
            f"/chat/completions?api-version={self._api_version}"
        )
        payload: dict[str, Any] = {
            "max_completion_tokens": _max_tokens(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = self._post(
            url,
            headers={"api-key": self._credential, "content-type": "application/json"},
            payload=payload,
        )
        msg = data["choices"][0].get("message", {})
        return str(msg.get("content") or "")


class GoogleProvider(_HTTPProvider):
    def _complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self._model}:generateContent?key={self._credential}"
        )
        payload: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": user}]}],
        }
        if json_mode:
            payload["generationConfig"] = {"response_mime_type": "application/json"}
        data = self._post(url, headers={"content-type": "application/json"}, payload=payload)
        return str(data["candidates"][0]["content"]["parts"][0]["text"])


class OllamaProvider(_HTTPProvider):
    """Modelo local (sem chave, sem redaction obrigatória — não sai da máquina)."""

    def _host(self) -> str:
        """Normaliza ``OLLAMA_HOST``: aceita ``localhost:11434`` (sem esquema),
        prefixando ``http://`` — senão a URL montada seria inválida."""
        host = self._credential.strip().rstrip("/")
        if "://" not in host:
            host = "http://" + host
        return host

    def _complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        payload: dict[str, Any] = {
            "model": self._model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            payload["format"] = "json"  # Ollama força JSON válido
        data = self._post(
            f"{self._host()}/api/chat",
            headers={"content-type": "application/json"},
            payload=payload,
        )
        return str(data["message"]["content"])

    def probe(self) -> tuple[bool, str]:
        """Reachability barata do Ollama: ``GET /api/tags`` (sem inferência) e
        confere se o modelo foi puxado — os dois modos reais de falha ("servidor
        offline" e "modelo não baixado"). Erro de conexão ⇒ servidor fora."""
        import httpx

        url = f"{self._host()}/api/tags"
        try:
            if self._client is not None:
                resp = self._client.get(url)
            else:
                resp = httpx.get(url, timeout=5.0)
            resp.raise_for_status()
            tags = resp.json()
        except Exception as exc:  # noqa: BLE001 — o objetivo é reportar a falha
            return False, f"servidor Ollama não respondeu em {self._host()} ({type(exc).__name__})"
        # Ollama lista 'nome:tag'; aceita match exato ou pelo nome sem a tag.
        names = {str(m.get("model", "")) for m in tags.get("models", [])}
        base = self._model.split(":")[0]
        if self._model in names or any(n.split(":")[0] == base for n in names):
            return True, f"Ollama online em {self._host()} · modelo '{self._model}' presente"
        return False, (
            f"servidor online, mas o modelo '{self._model}' NÃO foi puxado. "
            f"Rode:  ollama pull {self._model}"
        )


# --------------------------------------------------------------------------- #
# Registro de provedores (§ AI Providers) — modular e extensível.
#
# Adicionar um novo provedor é declarativo: implemente um ``_HTTPProvider`` (ou
# reuse ``_OpenAICompatProvider``) e registre um :class:`ProviderSpec`. O resto do
# sistema (CLI, onboarding, docs, seleção) descobre o provedor pelo registro —
# nenhum outro código muda. Chaves só por variável de ambiente (§5); model id
# nunca fabricado (§3.1): só a Anthropic tem default verificado, os demais exigem
# ``<PROVIDER>_MODEL``.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProviderSpec:
    """Descreve um provedor de IA: como construí-lo e onde ler as credenciais."""

    name: str
    label: str
    provider_cls: type[_HTTPProvider]
    key_env: str  # env com a credencial (ou host, no Ollama)
    model_env: str  # env com o id do modelo/deployment
    external: bool = True  # True → redaction antes de enviar
    default_model: str | None = None  # só onde o id é verificado (Anthropic)
    base_url_env: str | None = None  # env para sobrescrever o endpoint
    default_base_url: str | None = None
    scan_fit: str = ""  # nota de adequação ao projeto (docs/onboarding)
    timeout: float | None = None  # override do timeout (Ollama local precisa mais)
    # Mapa tier→modelo: {low,medium,high} → id. Preenchido só onde conseguimos
    # verificar os ids (Anthropic/OpenAI) e como defaults # VERIFICAR (Gemini). Onde
    # está vazio, o provedor continua exigindo <PROVIDER>_MODEL (anti-invenção §3.1).
    tier_models: dict[str, str] = field(default_factory=dict)
    # Credencial padrão para provedores LOCAIS que não exigem chave real (LM Studio
    # aceita qualquer string). None → exige a env (nuvem).
    default_credential: str | None = None

    def credential(self) -> str | None:
        return os.getenv(self.key_env) or self.default_credential

    def model(self) -> str | None:
        """Resolve o modelo: id explícito no env (override) > tier escolhido >
        default fixo. Assim o usuário escolhe só o NÍVEL e o EIGAN acha o modelo."""
        return (
            os.getenv(self.model_env) or self.tier_models.get(current_tier()) or self.default_model
        )

    def tier_model(self, tier: str) -> str | None:
        """Modelo que este provedor usaria no ``tier`` dado (para exibir na UI)."""
        return self.tier_models.get(tier) or self.default_model

    def configured(self) -> bool:
        """True se dá para instanciar (credencial + modelo + endpoint, se exigido)."""
        if not self.credential() or not self.model():
            return False
        if self.base_url_env is not None and not (
            os.getenv(self.base_url_env) or self.default_base_url
        ):
            return False
        return True

    def _timeout(self) -> float:
        """Timeout efetivo: env ``EIGAN_AI_TIMEOUT`` > override do spec > padrão."""
        env_t = os.getenv("EIGAN_AI_TIMEOUT")
        if env_t:
            try:
                return float(env_t)
            except ValueError:
                pass
        return self.timeout or _TIMEOUT

    def build(self, *, client: Any = None) -> _HTTPProvider | None:
        if not self.configured():
            return None
        kwargs: dict[str, Any] = {
            "model": self.model(),
            "credential": self.credential(),
            "redact_external": self.external,
            "timeout": self._timeout(),
            "client": client,
            "cache": ResponseCache(path=_ai_cache_path()),
        }
        if self.base_url_env is not None:
            kwargs["base_url"] = os.getenv(self.base_url_env) or self.default_base_url
        provider = self.provider_cls(**kwargs)
        # Só devolve um provedor **utilizável**: alguns exigem mais que credencial+
        # modelo (ex.: Azure precisa de api_version). Assim o gate AI-native
        # (require_provider) nunca aprova um provedor meio-configurado.
        return provider if provider.available() else None


PROVIDERS: dict[str, ProviderSpec] = {}
# Ordem de auto-detecção quando o usuário não escolhe explicitamente.
_PRIORITY = [
    "anthropic",
    "openai",
    "gemini",
    "openrouter",
    "groq",
    "together",
    "azure",
    "ollama",
    "lmstudio",
]


def register(spec: ProviderSpec) -> None:
    """Registra (ou substitui) um provedor pelo nome. Ponto de extensão único."""
    PROVIDERS[spec.name] = spec


def list_providers() -> list[ProviderSpec]:
    """Todos os provedores registrados, na ordem de prioridade conhecida."""
    known = [PROVIDERS[n] for n in _PRIORITY if n in PROVIDERS]
    extra = [s for n, s in PROVIDERS.items() if n not in _PRIORITY]
    return known + extra


for _spec in (
    ProviderSpec(
        "anthropic",
        "Anthropic (Claude)",
        AnthropicProvider,
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_MODEL",
        default_model=_DEFAULT_ANTHROPIC_MODEL,
        # ids verificados (claude-api skill): Haiku 4.5 / Sonnet 5 / Opus 4.8.
        tier_models={
            "low": "claude-haiku-4-5-20251001",
            "medium": "claude-sonnet-5",
            "high": "claude-opus-4-8",
        },
        scan_fit="Recomendado: melhor raciocínio de planejamento/narrativa; funciona só com a chave.",
    ),
    ProviderSpec(
        "openai",
        "OpenAI (GPT)",
        OpenAIProvider,
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        base_url_env="OPENAI_BASE_URL",
        default_base_url="https://api.openai.com/v1",
        # ids verificados contra a API real (GET /v1/models + completude de teste).
        tier_models={"low": "gpt-5-mini", "medium": "gpt-5", "high": "gpt-5.5"},
        scan_fit="Forte em análise e raciocínio; o nível escolhe o modelo (gpt-5-mini/gpt-5/gpt-5.5).",
    ),
    ProviderSpec(
        "gemini",
        "Google Gemini",
        GoogleProvider,
        "GOOGLE_API_KEY",
        "GOOGLE_MODEL",
        # defaults # VERIFICAR (sem chave para checar na fonte): confirme em
        # ai.google.dev/gemini-api/docs/models ou defina GOOGLE_MODEL.
        tier_models={
            "low": "gemini-2.5-flash",
            "medium": "gemini-2.5-pro",
            "high": "gemini-2.5-pro",
        },
        scan_fit="Bom custo/contexto longo; o nível escolhe o modelo (confirme os ids na doc).",
    ),
    ProviderSpec(
        "openrouter",
        "OpenRouter (multi-modelo)",
        OpenRouterProvider,
        "OPENROUTER_API_KEY",
        "OPENROUTER_MODEL",
        base_url_env="OPENROUTER_BASE_URL",
        default_base_url="https://openrouter.ai/api/v1",
        scan_fit="Um gateway p/ 300+ modelos: troque de modelo sem trocar de conta.",
    ),
    ProviderSpec(
        "groq",
        "Groq (baixa latência)",
        GroqProvider,
        "GROQ_API_KEY",
        "GROQ_MODEL",
        base_url_env="GROQ_BASE_URL",
        default_base_url="https://api.groq.com/openai/v1",
        scan_fit="Inferência muito rápida/barata: ideal p/ triagem e classificação.",
    ),
    ProviderSpec(
        "together",
        "Together AI",
        TogetherProvider,
        "TOGETHER_API_KEY",
        "TOGETHER_MODEL",
        base_url_env="TOGETHER_BASE_URL",
        default_base_url="https://api.together.xyz/v1",
        scan_fit="Modelos open-weight hospedados; bom p/ custo previsível.",
    ),
    ProviderSpec(
        "azure",
        "Azure OpenAI",
        AzureOpenAIProvider,
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_DEPLOYMENT",
        base_url_env="AZURE_OPENAI_ENDPOINT",
        scan_fit="Para empresas em Azure com governança/residência de dados.",
    ),
    ProviderSpec(
        "ollama",
        "Ollama (local, sem chave)",
        OllamaProvider,
        "OLLAMA_HOST",
        "OLLAMA_MODEL",
        external=False,
        timeout=_LOCAL_TIMEOUT,  # inferência local na CPU é lenta — timeout generoso
        scan_fit="Roda 100% local: nada sai da máquina (sem redaction externa). Privacidade máxima.",
    ),
    ProviderSpec(
        "lmstudio",
        "LM Studio (local, OpenAI-compat)",
        OpenAIProvider,  # LM Studio expõe a API OpenAI (usa max_completion_tokens)
        "LMSTUDIO_API_KEY",
        "LMSTUDIO_MODEL",
        base_url_env="LMSTUDIO_BASE_URL",
        default_base_url="http://localhost:1234/v1",
        default_credential="lm-studio",  # servidor local aceita qualquer chave
        external=False,  # local: nada sai da máquina (sem redaction)
        timeout=_LOCAL_TIMEOUT,
        scan_fit="Roda 100% local via LM Studio; exige LMSTUDIO_MODEL (o modelo carregado).",
    ),
):
    register(_spec)


def _config_default_provider() -> str | None:
    """Lê ``default:`` de ``config/ai.yaml`` (se existir) — seleção sem env."""
    path = Path("config") / "ai.yaml"
    if not path.is_file():
        return None
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — config quebrada nunca derruba o produto
        return None
    val = data.get("default") or data.get("provider")
    return str(val).strip().lower() if val else None


def default_provider(*, client: Any = None) -> AIProvider | None:
    """Resolve um provedor a partir de env/config. None se nada estiver
    configurado (use :func:`require_provider` quando a IA for obrigatória).

    Seleção: ``EIGAN_AI_PROVIDER`` (ou ``default:`` em ``config/ai.yaml``) escolhe
    explicitamente; senão auto-detecta na ordem de prioridade. Ollama é local (sem
    redaction); os externos exigem ``<PROVIDER>_MODEL`` (não fixamos id — §3.1)."""
    chosen = (os.getenv("EIGAN_AI_PROVIDER") or _config_default_provider() or "").strip().lower()
    if chosen:
        spec = PROVIDERS.get(chosen)
        return spec.build(client=client) if spec else None
    for spec in list_providers():
        provider = spec.build(client=client)
        if provider is not None:
            return provider
    return None


class AIProviderRequired(RuntimeError):
    """EIGAN é AI-native: sem provedor de IA configurado, não há scan (ADR-0012).

    Erro **acionável** (não é bug): diz exatamente como configurar um provedor.
    """


_NO_PROVIDER_MSG = (
    "EIGAN é um agente de IA — nenhum scan roda sem um provedor de IA configurado.\n"
    "Configure um (a chave vai para .env, fora do git, chmod 600):\n"
    "  • Fácil:  python3 eigan.py  →  Configuração  →  escolher provedor + colar a chave\n"
    "  • Manual: export EIGAN_AI_PROVIDER=<anthropic|openai|gemini|openrouter|groq|together|azure|ollama>\n"
    "            export <PROVIDER>_API_KEY=...   (e <PROVIDER>_MODEL, exceto Anthropic)\n"
    "  • Local:  Ollama (sem chave, sem custo, offline):\n"
    "            export EIGAN_AI_PROVIDER=ollama OLLAMA_HOST=http://localhost:11434 OLLAMA_MODEL=<modelo>\n"
    "Guia completo: docs/ai-providers.md"
)


def require_provider(*, client: Any = None) -> AIProvider:
    """Retorna o provedor de IA ativo ou levanta :class:`AIProviderRequired`.

    É o **gate AI-native** (§3.4/ADR-0012): os pontos de entrada de execução de
    scan chamam isto antes de rodar qualquer coisa — sem provedor, recusa com um
    erro acionável, nunca um stack trace."""
    provider = default_provider(client=client)
    if provider is None:
        raise AIProviderRequired(_NO_PROVIDER_MSG)
    return provider
