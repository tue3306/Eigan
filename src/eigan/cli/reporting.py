"""Geração de relatório para a CLI — compartilhado por ``report`` e wizard.

Suporta os cinco formatos (HTML/PDF/JSON/CSV/SARIF) e os dois modelos
(técnico/executivo). Todos funcionam sem IA; a IA só enriquece se houver chave.
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import __version__
from ..ai.provider import Enricher, default_provider
from ..findings.store import FindingStore
from ..knowledge.loader import KnowledgeBase
from ..report.deterministic import ReportGenerator

_KB_DIR = Path(__file__).resolve().parents[3] / "knowledge" / "skills"

_MACHINE = {"json", "csv", "sarif"}
TOOL_VERSION = __version__


def build_generator(
    *, use_ai: bool, feeds_meta: dict | None = None
) -> tuple[ReportGenerator, Enricher]:
    enricher = Enricher(KnowledgeBase(_KB_DIR), provider=default_provider() if use_ai else None)
    gen = ReportGenerator(enricher, tool_version=TOOL_VERSION, feeds_meta=feeds_meta or {})
    return gen, enricher


def write_report(
    store: FindingStore,
    scan_id: int,
    *,
    fmt: str,
    style: str,
    out: str | None,
    use_ai: bool,
    feeds_meta: dict | None = None,
    classification: str = "confidential",
    show_sensitive: bool = False,
) -> tuple[Path, bool]:
    """Gera o relatório e devolve (caminho, ia_usada). Levanta ValueError se o
    scan não existir.

    ``classification`` (público|interno|confidencial|restrito) dirige o destaque
    visual e o aviso; ``show_sensitive`` desliga o mascaramento de segredos
    (padrão: mascarado — §Tratamento de Informações Sensíveis)."""
    meta = store.get_scan(scan_id)
    if not meta:
        raise ValueError(f"Scan {scan_id} não encontrado.")
    findings = store.get_findings(scan_id)
    targets = json.loads(meta["targets"])
    engagement = meta["engagement"]
    scan_type = str(meta.get("profile", ""))  # ex.: "external/standard"
    mask = not show_sensitive

    gen, enricher = build_generator(use_ai=use_ai, feeds_meta=feeds_meta)
    out_path = Path(out or f"report_scan_{scan_id}_{style}.{fmt}")

    # Plano de remediação da IA (o que arrumar + como): reusa o gerado ao fim do
    # scan (web) ou gera sob demanda quando --ai (1 chamada, barata). Degrada sem
    # quebrar — formatos de máquina (json/csv/sarif) são serialização pura.
    ai_remediation = _load_remediation(store, scan_id) if fmt not in _MACHINE else None
    if ai_remediation is None and use_ai and fmt not in _MACHINE:
        from ..analysis.engine import remediate_and_store

        remediate_and_store(store, scan_id)  # nunca levanta; persiste se houver
        ai_remediation = _load_remediation(store, scan_id)

    if fmt in _MACHINE:
        out_path.write_text(gen.export(findings, fmt, engagement=engagement, targets=targets))
    elif fmt in ("md", "markdown"):
        from ..report.markdown import render_markdown

        out_path.write_text(
            render_markdown(
                findings,
                engagement=engagement,
                targets=targets,
                scan_type=scan_type,
                ai_analysis=store.get_analysis(scan_id) or "",
                ai_remediation=ai_remediation,
                tool_version=TOOL_VERSION,
                feeds_meta=feeds_meta,
                mask_sensitive=mask,
            )
        )
    elif fmt == "html":
        out_path.write_text(
            gen.render_html(
                findings,
                engagement=engagement,
                targets=targets,
                style=style,
                classification=classification,
                mask_sensitive=mask,
                scan_type=scan_type,
                ai_remediation=ai_remediation,
            )
        )
    else:  # pdf
        gen.render_pdf(
            findings,
            out_path,
            engagement=engagement,
            targets=targets,
            style=style,
            classification=classification,
            mask_sensitive=mask,
            scan_type=scan_type,
            ai_remediation=ai_remediation,
        )
    return out_path, enricher.ai_enabled


def _load_remediation(store: FindingStore, scan_id: int):
    """Plano de remediação já persistido para o scan (ou ``None``)."""
    from ..ai.remediation import plan_from_json

    return plan_from_json(store.get_remediation(scan_id))
