"""Relatório em Markdown — formato leve, versionável e legível em qualquer lugar.

Complementa HTML/PDF/JSON/CSV/SARIF. Traz as seções profissionais (sumário
executivo, escopo, metodologia, ferramentas, análise da IA, vulnerabilidades,
riscos, recomendações, conclusão). Determinístico na estrutura; a **Análise da
IA** é injetada quando existe (Analysis Engine).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..ai.context import severity_counts
from ..findings.schema import Finding, Severity
from .corporate import mask_sensitive as _mask_secrets

if TYPE_CHECKING:
    from ..ai.remediation import RemediationPlan

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _risk(f: Finding) -> float:
    return (
        f.risk.score
        if f.risk
        else float({"critical": 80, "high": 60, "medium": 40, "low": 20}.get(f.severity.value, 5))
    )


def _posture(counts: dict[str, int]) -> tuple[int, str]:
    score = 100
    for k, w in (("critical", 22), ("high", 11), ("medium", 4), ("low", 1)):
        score -= counts.get(k, 0) * w
    score = max(0, min(100, score))
    grade = (
        "A"
        if score >= 90
        else "B"
        if score >= 80
        else "C"
        if score >= 70
        else "D"
        if score >= 55
        else "E"
        if score >= 35
        else "F"
    )
    return score, grade


def render_markdown(
    findings: list[Finding],
    *,
    engagement: str = "",
    targets: list[str] | None = None,
    scan_type: str = "",
    ai_analysis: str = "",
    ai_remediation: "RemediationPlan | None" = None,
    tool_version: str = "",
    feeds_meta: dict | None = None,
    mask_sensitive: bool = True,
) -> str:
    # Mascaramento de segredos ligado por padrão — mesmo default do HTML/PDF
    # (``report.html.j2`` filtra ``f.evidence | mask``). Sem isto, ``--format md``
    # vazava chaves/tokens capturados em ``evidence`` que os outros formatos
    # ocultam (§Tratamento de Informações Sensíveis). ``--show-sensitive`` desliga.
    _mask = _mask_secrets if mask_sensitive else (lambda s: s)
    targets = targets or []
    counts = severity_counts(findings)
    score, grade = _posture(counts)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tools = sorted({f.source_tool for f in findings})
    ranked = sorted(findings, key=lambda f: (_risk(f), f.severity.rank), reverse=True)

    L: list[str] = []
    L.append(f"# Relatório EIGAN — {engagement or 'Avaliação de Segurança'}")
    L.append("")
    L.append(
        f"**Gerado:** {now}  ·  **Versão:** {tool_version or '—'}  ·  "
        f"**Tipo de scan:** {scan_type or '—'}"
    )
    L.append(f"**Alvos:** {', '.join(targets) or '—'}")
    L.append("")
    L.append(
        "> ⚠️ Documento confidencial — uso autorizado apenas. Metodologia: PTES / NIST SP 800-115."
    )
    L.append("")

    # Sumário executivo
    L.append("## Sumário executivo")
    L.append("")
    L.append(f"- **Postura de segurança:** {score}/100 (nota {grade})")
    L.append(f"- **Total de findings:** {len(findings)}")
    L.append(
        "- **Por severidade:** "
        + " · ".join(f"{_SEV_EMOJI[s]} {s.value} {counts.get(s.value, 0)}" for s in Severity)
    )
    kev = sum(1 for f in findings if f.risk and f.risk.kev)
    if kev:
        L.append(f"- **Em exploração ativa (CISA KEV):** {kev}")
    L.append("")

    # Análise da IA
    if ai_analysis.strip():
        L.append("## Análise da IA")
        L.append("")
        L.append(ai_analysis.strip())
        L.append("")

    # Escopo + metodologia + ferramentas
    L.append("## Escopo")
    L.append("")
    for t in targets:
        L.append(f"- `{t}`")
    L.append("")
    L.append("## Ferramentas utilizadas")
    L.append("")
    L.append(", ".join(f"`{t}`" for t in tools) or "—")
    L.append("")

    # Vulnerabilidades / resultados
    L.append("## Vulnerabilidades e resultados")
    L.append("")
    L.append("| # | Sev. | Risco | Título | Ativo | CWE | Fonte |")
    L.append("|---|------|-------|--------|-------|-----|-------|")
    for i, f in enumerate(ranked, start=1):
        title = f.title.replace("|", "\\|")[:80]  # escapa pipe (fora da f-string: py311)
        L.append(
            f"| {i} | {_SEV_EMOJI[f.severity]} {f.severity.value} | {_risk(f):.0f} | "
            f"{title} | `{f.affected_asset[:50]}` | {f.cwe or '—'} | {f.source_tool} |"
        )
    L.append("")

    # Detalhe dos mais graves
    top = [f for f in ranked if f.severity.rank >= Severity.MEDIUM.rank][:15]
    if top:
        L.append("## Riscos priorizados (detalhe)")
        L.append("")
        for f in top:
            L.append(f"### {_SEV_EMOJI[f.severity]} {f.title}")
            L.append("")
            L.append(f"- **Ativo:** `{f.affected_asset}`  ·  **Fonte:** {f.source_tool}")
            if f.cwe or f.owasp:
                L.append(f"- **Classificação:** {f.cwe or ''} {f.owasp or ''}".rstrip())
            if f.description:
                L.append(f"- **Descrição:** {_mask(f.description)}")
            if f.evidence:
                # Mascara ANTES de truncar: um segredo perto do corte de 200 não
                # pode escapar pela borda da truncagem.
                L.append(f"- **Evidência:** `{_mask(f.evidence).strip()[:200]}`")
            L.append("")

    # Plano de remediação da IA (o que arrumar + como)
    if ai_remediation is not None and not ai_remediation.is_empty():
        L.append("## Plano de remediação priorizado (IA)")
        L.append("")
        L.append(
            "> Sugestões geradas por IA (*o que corrigir e como*), priorizadas por risco. "
            "Grounded nos achados; revise antes de aplicar."
        )
        L.append("")
        if ai_remediation.summary.strip():
            L.append(ai_remediation.summary.strip())
            L.append("")
        if ai_remediation.items:
            L.append("| Prio. | Problema / Ativo | O que corrigir | Como corrigir | Esforço |")
            L.append("|-------|------------------|----------------|---------------|---------|")
            for it in ai_remediation.items:
                asset = f" (`{it.asset}`)" if it.asset else ""
                title = (it.title or "—").replace("|", "\\|")
                what = (it.what or "—").replace("|", "\\|")
                how = (it.how or "—").replace("|", "\\|")
                L.append(
                    f"| {it.priority or '—'} | {title}{asset} | {what} | {how} | "
                    f"{it.effort or '—'} |"
                )
        elif ai_remediation.text.strip():
            L.append(ai_remediation.text.strip())
        L.append("")

    L.append("## Recomendações e próximos passos")
    L.append("")
    if ai_analysis.strip():
        L.append(
            "Ver a seção **Análise da IA** acima (correlações, falsos-positivos e ações priorizadas)."
        )
    else:
        L.append("- Priorizar a correção dos itens Críticos e Altos.")
        L.append("- Revisar exposições sensíveis (arquivos/paineis não autenticados).")
        L.append("- Aplicar o princípio do menor privilégio e endurecer serviços expostos.")
    L.append("")
    L.append("## Conclusão")
    L.append("")
    L.append(
        f"A avaliação de {', '.join(targets) or 'o(s) alvo(s)'} resultou em {len(findings)} "
        f"finding(s) (postura {score}/100, nota {grade}). "
        + (
            "Há itens críticos que exigem ação imediata."
            if counts.get("critical")
            else "Sem itens críticos; siga o plano de remediação priorizado."
        )
    )
    L.append("")
    L.append("---")
    L.append(f"*Gerado por EIGAN {tool_version or ''} — a IA é a ferramenta.*")
    return "\n".join(L)
