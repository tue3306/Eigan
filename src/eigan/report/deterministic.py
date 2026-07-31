"""Gerador de relatórios — Técnico e Executivo, em HTML/PDF + exporters.

Modo determinístico por padrão (§11): monta o relatório a partir dos findings +
correlação + base de conhecimento, **sem nenhuma chave de API**. O sumário
executivo e as narrativas por IA são opcionais e caem automaticamente para o
texto determinístico se ausentes.

Saídas: HTML sempre; PDF requer WeasyPrint (opcional); JSON/CSV/SARIF via
:mod:`eigan.report.exporters` (todos sem IA).
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, pass_context

from ..ai.provider import Enricher
from ..ai.remediation import RemediationPlan
from ..analysis.attack import map_attack
from ..analysis.inventory import build_inventory, summarize
from ..engine.correlation import AssetCorrelation, correlate_assets
from ..findings.schema import Finding, Severity
from . import corporate, exporters
from .corporate import Classification

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# Índice (número, título) por estilo — mantém o TOC e os <h2> em sincronia.
_TOC_TECHNICAL = [
    (1, "Sumário executivo"),
    (2, "Escopo e metodologia"),
    (3, "Postura de risco"),
    (4, "Findings — visão geral"),
    (5, "Detalhamento técnico"),
    (6, "Inventário de ativos"),
    (7, "Cobertura MITRE ATT&CK"),
    (8, "Recomendações e remediação"),
]
_TOC_EXECUTIVE = [
    (1, "Sumário executivo"),
    (2, "Postura de risco"),
    (3, "Riscos prioritários"),
    (4, "Ativos mais críticos"),
    (5, "Cobertura MITRE ATT&CK"),
    (6, "Recomendações"),
]


def _toc_with_remediation(
    base: list[tuple[int, str]], plan: RemediationPlan | None
) -> list[tuple[int, str]]:
    """Acrescenta a seção 'Plano de remediação (IA)' ao índice só quando há plano."""
    if plan is None or plan.is_empty():
        return base
    return [*base, (base[-1][0] + 1, "Plano de remediação (IA)")]


def _dataset_hash(findings: list[Finding]) -> str:
    blob = json.dumps([f.model_dump(mode="json") for f in findings], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


class ReportGenerator:
    def __init__(
        self,
        enricher: Enricher,
        *,
        brand: str = "EIGAN",
        tool_version: str = "0.0.0",
        feeds_meta: dict | None = None,
    ) -> None:
        self._enricher = enricher
        self._brand = brand
        self._tool_version = tool_version
        self._feeds_meta = feeds_meta or {}
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            # autoescape SEMPRE: os templates têm extensão .html.j2, e
            # select_autoescape(["html","xml"]) NÃO os reconhece (casa pela extensão
            # final, que é .j2) — deixava a saída SEM escape → XSS armazenado no
            # relatório a partir de dado do alvo (title/evidence/asset). Todos os
            # templates deste env são HTML; os únicos trechos de HTML cru (SVGs dos
            # gráficos) já usam |safe. (segurança §4.2/§23; CWE-79)
            autoescape=True,
        )

        # Filtro de mascaramento: só oculta segredos quando o contexto pede
        # (mask_sensitive=True). Fica ligado ao contexto para não duplicar a
        # decisão em cada template (§Tratamento de Informações Sensíveis).
        @pass_context
        def _mask(ctx: object, value: object) -> str:
            text = str(value)
            enabled = getattr(ctx, "get", lambda *_: False)("mask_sensitive")
            return corporate.mask_sensitive(text) if enabled else text

        self._env.filters["mask"] = _mask

    # ── metadados comuns ────────────────────────────────────────────────────────
    def _base_meta(self, findings: list[Finding], engagement: str, targets: list[str]) -> dict:
        return {
            "brand": self._brand,
            "engagement": engagement,
            "targets": targets,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "tool_version": self._tool_version,
            "dataset_hash": _dataset_hash(findings),
            "feeds": {
                "kev": self._feeds_meta.get("kev", ""),
                "epss": self._feeds_meta.get("epss", ""),
            },
        }

    def _summary(self, findings: list[Finding]) -> dict[str, int]:
        counts = Counter(f.severity for f in findings)
        return {s.value: counts.get(s, 0) for s in _SEV_ORDER}

    def _corporate_ctx(
        self,
        findings: list[Finding],
        engagement: str,
        targets: list[str],
        *,
        classification: str | Classification,
        scan_type: str,
        mask_sensitive: bool,
    ) -> dict:
        """Base + primitivas corporativas: classificação, id único, score de
        postura, gráficos SVG, ferramentas executadas e o flag de mascaramento."""
        meta = self._base_meta(findings, engagement, targets)
        cls = Classification.from_str(classification)
        summary = self._summary(findings)
        score = corporate.security_score(findings)
        meta.update(
            {
                "classification": cls,
                "report_id": corporate.report_id(meta["dataset_hash"]),
                "scan_type": scan_type,
                "security_score": score,
                "summary": summary,
                "donut_svg": corporate.severity_donut_svg(summary),
                "gauge_svg": corporate.score_gauge_svg(score),
                "sev_colors": corporate._SEV_COLOR,
                "mask_sensitive": mask_sensitive,
                "tools_executed": sorted(
                    {f.source_tool for f in findings}
                    | {s for f in findings for s in f.correlated_sources}
                ),
            }
        )
        return meta

    # ── relatório técnico (detalhado) ───────────────────────────────────────────
    def render_html(
        self,
        findings: list[Finding],
        *,
        engagement: str,
        targets: list[str],
        executive_summary: str = "",
        style: str = "technical",
        classification: str | Classification = "confidential",
        mask_sensitive: bool = True,
        scan_type: str = "",
        ai_remediation: RemediationPlan | None = None,
    ) -> str:
        if style == "executive":
            return self.render_executive_html(
                findings,
                engagement=engagement,
                targets=targets,
                executive_summary=executive_summary,
                classification=classification,
                mask_sensitive=mask_sensitive,
                scan_type=scan_type,
                ai_remediation=ai_remediation,
            )
        ctx = self._corporate_ctx(
            findings,
            engagement,
            targets,
            classification=classification,
            scan_type=scan_type,
            mask_sensitive=mask_sensitive,
        )
        inventory = build_inventory(findings)
        kev_count = sum(1 for f in findings if f.risk and f.risk.kev)
        summary = ctx["summary"]
        ai = bool(executive_summary) and self._enricher.ai_enabled
        if not executive_summary:
            executive_summary = self._deterministic_executive(
                findings, correlate_assets(findings), summary, kev_count
            )
        ctx.update(
            {
                "findings": findings,
                "enrichment": self._enricher.explain_all(findings),
                "executive_summary": executive_summary,
                "executive_ai": ai,
                "inventory": inventory,
                "inventory_summary": summarize(inventory),
                "kev_count": kev_count,
                "attack": map_attack(findings),
                "recommendations": self._recommendations(findings),
                "ai_remediation": ai_remediation,
                "toc": _toc_with_remediation(_TOC_TECHNICAL, ai_remediation),
            }
        )
        return self._env.get_template("report.html.j2").render(**ctx)

    # ── relatório executivo (risco/negócio) ─────────────────────────────────────
    def render_executive_html(
        self,
        findings: list[Finding],
        *,
        engagement: str,
        targets: list[str],
        executive_summary: str = "",
        classification: str | Classification = "confidential",
        mask_sensitive: bool = True,
        scan_type: str = "",
        ai_remediation: RemediationPlan | None = None,
    ) -> str:
        correlations = correlate_assets(findings)
        ctx = self._corporate_ctx(
            findings,
            engagement,
            targets,
            classification=classification,
            scan_type=scan_type,
            mask_sensitive=mask_sensitive,
        )
        summary = ctx["summary"]
        kev_count = sum(1 for f in findings if f.risk and f.risk.kev)
        top_risks = sorted(findings, key=lambda f: f.risk_rank, reverse=True)[:15]

        ai = bool(executive_summary) and self._enricher.ai_enabled
        if not executive_summary:
            executive_summary = self._deterministic_executive(
                findings, correlations, summary, kev_count
            )

        inventory = build_inventory(findings)
        ctx.update(
            {
                "correlations": correlations,
                "kev_count": kev_count,
                "top_risks": top_risks,
                "recommendations": self._recommendations(findings),
                "executive_summary": executive_summary,
                "executive_ai": ai,
                "attack": map_attack(findings),  # Purple: cobertura ATT&CK + gap
                "inventory_summary": summarize(inventory),  # Blue: números do inventário
                "ai_remediation": ai_remediation,
                "toc": _toc_with_remediation(_TOC_EXECUTIVE, ai_remediation),
            }
        )
        return self._env.get_template("executive.html.j2").render(**ctx)

    def _deterministic_executive(
        self,
        findings: list[Finding],
        correlations: list[AssetCorrelation],
        summary: dict[str, int],
        kev_count: int,
    ) -> str:
        na = len(correlations)
        crit, high = summary.get("critical", 0), summary.get("high", 0)
        parts = [f"A avaliação cobriu {na} ativo(s) e identificou {len(findings)} achado(s)."]
        if crit or high:
            parts.append(
                f"Destes, {crit} de severidade crítica e {high} alta requerem atenção prioritária."
            )
        else:
            parts.append("Nenhum achado de severidade alta ou crítica foi identificado.")
        if kev_count:
            parts.append(
                f"{kev_count} correspondem a vulnerabilidades com exploração ativa "
                "conhecida (CISA KEV), exigindo correção imediata."
            )
        xp = sum(1 for a in correlations if a.cross_perspective)
        if xp:
            parts.append(
                f"{xp} ativo(s) apresentam exposição externa e interna, ampliando a "
                "superfície de ataque."
            )
        return " ".join(parts)

    def _recommendations(self, findings: list[Finding]) -> list[str]:
        recs: list[str] = []
        kev = sorted({f.title for f in findings if f.risk and f.risk.kev})
        if kev:
            recs.append(
                "Priorizar a correção imediata dos itens em CISA KEV (exploração ativa): "
                + "; ".join(kev[:5])
                + (" …" if len(kev) > 5 else "")
                + "."
            )
        for f in sorted(findings, key=lambda f: f.risk_rank, reverse=True)[:5]:
            rem = self._enricher.explain(f).remediation.strip()
            if rem:
                first = rem.splitlines()[0][:200]
                line = f"{f.title}: {first}"
                if line not in recs:
                    recs.append(line)
        if not recs:
            recs.append(
                "Manter processo contínuo de gestão de vulnerabilidades e aplicar "
                "hardening (CIS Benchmarks / NIST SP 800-53)."
            )
        return recs

    # ── PDF (opcional) ──────────────────────────────────────────────────────────
    def render_pdf(
        self,
        findings: list[Finding],
        out_path: str | Path,
        *,
        engagement: str,
        targets: list[str],
        executive_summary: str = "",
        style: str = "technical",
        classification: str | Classification = "confidential",
        mask_sensitive: bool = True,
        scan_type: str = "",
        ai_remediation: RemediationPlan | None = None,
    ) -> Path:
        html = self.render_html(
            findings,
            engagement=engagement,
            targets=targets,
            executive_summary=executive_summary,
            style=style,
            classification=classification,
            mask_sensitive=mask_sensitive,
            scan_type=scan_type,
            ai_remediation=ai_remediation,
        )
        out = Path(out_path)
        # PDF é opcional (§12): ImportError = extra ausente; OSError = libs
        # nativas (Pango/GDK-Pixbuf) faltando. Ambos viram um erro acionável e o
        # chamador degrada para HTML — nunca stack trace cru (§13).
        try:
            from weasyprint import HTML  # import tardio: PDF é opcional

            HTML(string=html).write_pdf(str(out))
        except (ImportError, OSError) as exc:
            raise RuntimeError(
                "PDF indisponível (WeasyPrint ausente ou libs de sistema faltando). "
                "Instale 'eigan[pdf]' + libs (veja `eigan doctor`) ou use HTML."
            ) from exc
        return out

    # ── exporters de máquina (JSON/CSV/SARIF — sem IA) ──────────────────────────
    def export(
        self, findings: list[Finding], fmt: str, *, engagement: str, targets: list[str]
    ) -> str:
        meta = self._base_meta(findings, engagement, targets)
        if fmt == "json":
            return exporters.to_json(findings, meta=meta)
        if fmt == "csv":
            return exporters.to_csv(findings)
        if fmt == "sarif":
            return exporters.to_sarif(findings, tool_version=self._tool_version, meta=meta)
        raise ValueError(f"Formato de export desconhecido: {fmt!r}. Use json|csv|sarif.")
