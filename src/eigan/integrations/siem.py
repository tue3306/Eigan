"""Export nativo para SIEM em CEF (Common Event Format) — §16.2.

CEF é um formato de linha amplamente ingerido por SIEMs. Seguimos a **especificação
oficial** (cabeçalho com 7 campos separados por ``|``; extensão em pares ``chave=valor``),
incluindo as regras de **escape** (``\\`` e ``|`` no cabeçalho; ``\\``, ``=`` e nova linha
na extensão). Determinístico e reprodutível (mesmos findings ⇒ mesma saída). Redige campos
textuais (P8) para não vazar segredo/PII nos logs do SIEM.

Não fabricamos esquema (P1): o mapeamento de severidade CEF (0–10) e a estrutura seguem a
definição pública do CEF.
"""

from __future__ import annotations

from .. import __version__
from ..ai.sanitize import redact
from ..findings.schema import Finding, Severity

_VENDOR = "EIGAN"
_PRODUCT = "EIGAN"

# Severidade CEF é 0–10; mapeamento a partir da severidade qualitativa do finding.
_CEF_SEVERITY: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 5,
    Severity.HIGH: 7,
    Severity.CRITICAL: 9,
}


def _escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_ext(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\n")


def _extensions(finding: Finding) -> str:
    # Pares chave=valor em ordem fixa (determinismo). Chaves CEF padrão onde há
    # equivalente (dst=alvo, cs1=CWE, cs2=OWASP); demais como campos próprios.
    pairs: list[tuple[str, str]] = [
        ("dst", redact(finding.affected_asset)),
        ("cs1", finding.cwe or ""),
        ("cs1Label", "CWE"),
        ("cs2", finding.owasp or ""),
        ("cs2Label", "OWASP"),
        ("eiganTool", finding.source_tool),
        ("eiganStatus", finding.status.value),
        ("eiganFingerprint", finding.fingerprint),
    ]
    return " ".join(f"{k}={_escape_ext(v)}" for k, v in pairs if v != "")


def finding_to_cef(finding: Finding) -> str:
    """Converte um finding numa linha CEF válida e determinística."""
    header = "|".join(
        [
            "CEF:0",
            _escape_header(_VENDOR),
            _escape_header(_PRODUCT),
            _escape_header(__version__),
            _escape_header(finding.cwe or finding.fingerprint),  # Signature ID
            _escape_header(redact(finding.title)),  # Name
            str(_CEF_SEVERITY[finding.severity]),
        ]
    )
    ext = _extensions(finding)
    return f"{header}|{ext}" if ext else f"{header}|"


def to_cef(findings: list[Finding]) -> str:
    """Exporta uma lista de findings como CEF (uma linha por finding)."""
    return "\n".join(finding_to_cef(f) for f in findings)
