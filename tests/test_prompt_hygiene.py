"""Higiene de contexto + versionamento de prompt (§2.7).

Versionamento: os system prompts de IA são artefatos versionados por hash. Mudar um
prompt QUEBRA o teste de propósito — o autor deve (a) atualizar o hash e (b)
reexecutar os evals de decisão (§3.1) para revalidar a regressão. Também guarda
contra inchaço: um prompt maior é dívida de custo e precisa justificar os tokens.

Poda de contexto: a cada onda o Planner envia só o DELTA (novos findings, limitado),
não o histórico acumulado reenviado — os tokens por onda não crescem com o scan.
"""

from __future__ import annotations

import hashlib

from eigan.ai import provider as pv
from eigan.capability import Capability
from eigan.engine.cognitive import planner as pl
from eigan.engine.cognitive.feedback import Feedback, ScanState
from eigan.engine.cognitive.planner import _summarize_findings
from eigan.findings.schema import Finding, Severity

# Hashes fixados dos system prompts (SHA-256[:16]). Ao mudar um prompt de propósito,
# atualize o hash correspondente E reexecute os evals de decisão (§3.1).
_PINNED = {
    "AGENTIC_SYSTEM": "cd4dd8da7d702349",
    "AI_SYSTEM": "1371796e3fe1252f",
    # Atualizado ao adicionar a regra anti-injeção (DADOS-DO-ALVO não-confiáveis)
    # ao prompt do explain — a mesma higiene que as outras superfícies de IA já
    # tinham. Evals de decisão (§3.1) revalidados. Ver test_audit_fixes.py.
    "SYSTEM_PROMPT": "34bd0c12636a42aa",
}


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def test_agentic_system_prompt_pinned() -> None:
    assert _h(pl._AGENTIC_SYSTEM) == _PINNED["AGENTIC_SYSTEM"], (
        "O system prompt do AgenticPlanner mudou. Se foi de propósito: atualize o hash "
        "aqui e reexecute os evals de decisão (§3.1) para revalidar a regressão."
    )


def test_ai_system_prompt_pinned() -> None:
    assert _h(pl._AI_SYSTEM) == _PINNED["AI_SYSTEM"]


def test_enrichment_system_prompt_pinned() -> None:
    assert _h(pv._SYSTEM_PROMPT) == _PINNED["SYSTEM_PROMPT"]


def test_summarize_findings_is_bounded() -> None:
    # O resumo enviado à IA é limitado: o contexto não cresce com o total de findings.
    findings = [
        Finding(title=f"f{i}", severity=Severity.LOW, affected_asset=f"a{i}", source_tool="t")
        for i in range(50)
    ]
    out = _summarize_findings(findings, limit=12)
    assert out.count("- [") == 12  # só 12 linhas de finding
    assert "+38" in out  # e um resumo do restante (50 - 12)


def test_context_pruned_after_replan() -> None:
    # Poda de contexto (§2.7): mark_replanned consome o delta — as ondas seguintes
    # enviam só o novo, não o histórico acumulado.
    state = ScanState()
    fs = [Finding(title="x", severity=Severity.LOW, affected_asset="a", source_tool="t")]
    state.absorb(Feedback(Capability.PORT_DISCOVERY, "nmap", fs, 0.1))
    assert state.new_findings  # há delta desde o último replan
    state.mark_replanned()
    assert state.new_findings == []  # delta consumido → não reenviado na próxima onda
    assert state.findings  # o histórico total permanece (relatório), mas fora do prompt
