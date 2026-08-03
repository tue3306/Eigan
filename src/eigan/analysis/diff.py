"""Memória entre scans — diff determinístico (Pilar 2 / ADR-0008).

Compara dois scans do mesmo alvo e responde *o que mudou*: findings **novos**,
**corrigidos** (sumiram) e **persistentes**, além de **novos ativos** e **novos
serviços/portas**. Tudo por igualdade de `fingerprint` (determinístico, ADR-0007
já garante que mesma vuln de fontes diferentes tem o mesmo fingerprint) — a IA
**não** decide o diff, só o *narra* (função opcional, com fallback).

Módulo de aplicação/análise: consome o domínio (`Finding`) e não faz I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..findings.schema import Finding, Severity
from ..perspective import extract_host

# porta ao final de ``host:porta`` — reaproveita a convenção dos parsers de rede.
_PORT_RE = re.compile(r":(\d{1,5})(?:/\w+)?$")


def _asset_host(asset: str) -> str:
    """Host canônico do ativo (IP, hostname, host:port ou URL).

    Usa a MESMA normalização (``extract_host``) que inventory/correlation/graph —
    senão dois caminhos do mesmo host (``http://alvo/app`` vs ``http://alvo/login``)
    viram "ativos" distintos e o diff reporta "novo(s) ativo(s)" falso."""
    return extract_host(asset)


def _port_of(asset: str) -> str | None:
    """Porta explícita do ativo (``host:port`` ou URL com porta), senão ``None``."""
    a = asset.strip()
    if "://" in a:
        try:
            port = urlsplit(a).port
        except ValueError:
            return None
        return str(port) if port else None
    m = _PORT_RE.search(a)
    return m.group(1) if m else None


def _service_key(asset: str) -> str | None:
    """Serviço canônico ``host:port`` do ativo, ou ``None`` se sem porta explícita.

    Normaliza por host+porta (não pela string crua) para que dois caminhos do
    mesmo ``host:port`` não contem como serviço novo."""
    port = _port_of(asset)
    if port is None:
        return None
    return f"{_asset_host(asset)}:{port}"


@dataclass
class ScanDiff:
    """Resultado da comparação entre um scan anterior e o atual."""

    previous_scan_id: int | None
    current_scan_id: int | None
    new: list[Finding] = field(default_factory=list)  # apareceram agora
    resolved: list[Finding] = field(default_factory=list)  # sumiram desde a última
    persisting: list[Finding] = field(default_factory=list)  # continuam presentes
    new_assets: list[str] = field(default_factory=list)
    new_services: list[str] = field(default_factory=list)  # "host:porta" novos

    @property
    def changed(self) -> bool:
        return bool(self.new or self.resolved or self.new_assets or self.new_services)

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "resolved": len(self.resolved),
            "persisting": len(self.persisting),
            "new_assets": len(self.new_assets),
            "new_services": len(self.new_services),
        }

    def summary(self) -> str:
        """Narrativa **determinística** da mudança (sempre disponível, sem IA)."""
        if self.previous_scan_id is None:
            return (
                f"Primeira vez que este alvo é escaneado (scan #{self.current_scan_id}): "
                f"{len(self.new)} finding(s) de baseline, sem histórico para comparar."
            )
        if not self.changed:
            return (
                f"Sem mudanças desde o scan #{self.previous_scan_id}: "
                f"{len(self.persisting)} finding(s) persistem, nada novo nem corrigido."
            )
        parts: list[str] = []
        if self.new:
            crit = sum(1 for f in self.new if f.severity.rank >= Severity.HIGH.rank)
            extra = f" ({crit} alta/crítica)" if crit else ""
            parts.append(f"{len(self.new)} novo(s){extra}")
        if self.resolved:
            parts.append(f"{len(self.resolved)} corrigido(s)")
        if self.persisting:
            parts.append(f"{len(self.persisting)} persistente(s)")
        if self.new_services:
            parts.append(f"{len(self.new_services)} novo(s) serviço(s)")
        if self.new_assets:
            parts.append(f"{len(self.new_assets)} novo(s) ativo(s)")
        return f"Desde o scan #{self.previous_scan_id}: " + ", ".join(parts) + "."


def diff_findings(
    previous: list[Finding],
    current: list[Finding],
    *,
    previous_scan_id: int | None = None,
    current_scan_id: int | None = None,
) -> ScanDiff:
    """Diffa dois conjuntos de findings por ``fingerprint`` (determinístico)."""
    prev_by_fp = {f.fingerprint: f for f in previous}
    cur_by_fp = {f.fingerprint: f for f in current}

    new = [cur_by_fp[fp] for fp in cur_by_fp if fp not in prev_by_fp]
    resolved = [prev_by_fp[fp] for fp in prev_by_fp if fp not in cur_by_fp]
    persisting = [cur_by_fp[fp] for fp in cur_by_fp if fp in prev_by_fp]

    prev_assets = {_asset_host(f.affected_asset) for f in previous}
    cur_assets = {_asset_host(f.affected_asset) for f in current}
    new_assets = sorted(cur_assets - prev_assets)

    prev_services = {k for f in previous if (k := _service_key(f.affected_asset)) is not None}
    cur_services = {k for f in current if (k := _service_key(f.affected_asset)) is not None}
    new_services = sorted(cur_services - prev_services)

    # ordena por risco/severidade para leitura (mais grave primeiro).
    key = lambda f: (f.risk_rank, f.severity.rank)  # noqa: E731
    return ScanDiff(
        previous_scan_id=previous_scan_id,
        current_scan_id=current_scan_id,
        new=sorted(new, key=key, reverse=True),
        resolved=sorted(resolved, key=key, reverse=True),
        persisting=sorted(persisting, key=key, reverse=True),
        new_assets=new_assets,
        new_services=new_services,
    )
