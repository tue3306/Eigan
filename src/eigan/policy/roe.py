"""Regras de Engajamento (RoE) como artefato de 1ª classe (§18.1).

O gate de escopo diz *contra o quê* se pode agir; o RoE diz *como, quando e até que
ponto*. Um engajamento profissional declara, além do escopo:

- **janelas de tempo permitidas** (blackout fora do horário — não tocar produção em
  horário de pico);
- **exclusões** (hosts/portas/paths proibidos mesmo dentro do escopo);
- **classe de teste máxima autorizada** (recon sim, exploração não — reusa
  :class:`ImpactClass`);
- **tetos de taxa por alvo** (não derrubar produção);
- **contatos de emergência**.

É domínio puro (sem I/O de rede), trivialmente testável. Uma ação que viola o RoE é
bloqueada como :class:`RoEViolation` — subclasse de
:class:`~eigan.security.scope.ScopeViolation`, para que todo handler que já barra
violação de escopo também barre violação de RoE (defesa em profundidade, P3). O
``digest()`` permite referenciar o RoE na trilha de auditoria (§18.3) e na autorização
assinável (§18.4). O enforcement do teto de taxa no paralelismo real é o §23.1; aqui
o RoE **declara** o teto e expõe o intervalo mínimo derivado.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, time
from pathlib import Path
from typing import Any

import yaml

from ..perspective import extract_host
from ..security.scope import Scope, ScopeViolation
from .impact import ImpactClass


class RoEViolation(ScopeViolation):
    """Ação que viola as Regras de Engajamento (janela, exclusão, classe, etc.)."""


_WEEKDAYS: dict[str, int] = {
    "seg": 0, "mon": 0, "ter": 1, "tue": 1, "qua": 2, "wed": 2,
    "qui": 3, "thu": 3, "sex": 4, "fri": 4, "sab": 5, "sat": 5, "dom": 6, "sun": 6,
}  # fmt: skip


def _parse_time(value: Any) -> time:
    if isinstance(value, time):
        return value
    parts = str(value).split(":")
    hh = int(parts[0])
    mm = int(parts[1]) if len(parts) > 1 else 0
    return time(hh, mm)


def _parse_weekday(value: Any) -> int:
    if isinstance(value, int):
        return value % 7
    return _WEEKDAYS[str(value).strip().lower()[:3]]


@dataclass(frozen=True)
class TimeWindow:
    """Janela permitida: dias da semana + intervalo de horário (suporta atravessar a
    meia-noite quando ``start`` > ``end``, ex.: 22:00–06:00)."""

    weekdays: frozenset[int] = field(default_factory=lambda: frozenset(range(7)))
    start: time = time(0, 0)
    end: time = time(23, 59, 59)

    def contains(self, dt: datetime) -> bool:
        if dt.weekday() not in self.weekdays:
            return False
        moment = dt.time()
        if self.start <= self.end:
            return self.start <= moment <= self.end
        return moment >= self.start or moment <= self.end  # janela overnight

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimeWindow:
        wd = data.get("weekdays")
        weekdays = frozenset(_parse_weekday(w) for w in wd) if wd else frozenset(range(7))
        return cls(
            weekdays=weekdays,
            start=_parse_time(data.get("start", "00:00")),
            end=_parse_time(data.get("end", "23:59")),
        )


@dataclass(frozen=True)
class RateLimit:
    """Teto de taxa por alvo. O mais restritivo entre os campos definidos vale."""

    max_per_second: float | None = None
    max_per_minute: float | None = None

    def min_interval_seconds(self) -> float | None:
        """Intervalo mínimo entre requisições ao mesmo alvo (o teto mais restritivo)."""
        intervals = []
        if self.max_per_second and self.max_per_second > 0:
            intervals.append(1.0 / self.max_per_second)
        if self.max_per_minute and self.max_per_minute > 0:
            intervals.append(60.0 / self.max_per_minute)
        return max(intervals) if intervals else None


@dataclass(frozen=True)
class Action:
    """Ação ativa a ser avaliada contra o RoE."""

    target: str
    impact: ImpactClass
    at: datetime
    port: int | None = None
    path: str | None = None


@dataclass(frozen=True)
class RoEDecision:
    """Resultado da avaliação de uma ação contra o RoE."""

    allowed: bool
    reason: str | None = None


@dataclass
class RulesOfEngagement:
    """Regras de Engajamento declarativas por engajamento."""

    engagement: str = ""
    windows: list[TimeWindow] = field(default_factory=list)  # vazio = sempre permitido
    exclude_hosts: list[str] = field(default_factory=list)
    exclude_ports: frozenset[int] = field(default_factory=frozenset)
    exclude_paths: list[str] = field(default_factory=list)
    max_impact: ImpactClass = ImpactClass.ACTIVE_SAFE
    rate_limit: RateLimit | None = None
    emergency_contacts: list[str] = field(default_factory=list)

    def evaluate(self, action: Action) -> RoEDecision:
        """Avalia uma ação; devolve permitido/bloqueado + motivo (não levanta)."""
        if self.windows and not any(w.contains(action.at) for w in self.windows):
            return RoEDecision(False, "fora da janela permitida (blackout)")

        host = extract_host(action.target)
        if any(Scope._matches(host, ex) for ex in self.exclude_hosts):
            return RoEDecision(False, f"host {host} excluído pelo RoE")

        if action.port is not None and action.port in self.exclude_ports:
            return RoEDecision(False, f"porta {action.port} excluída pelo RoE")

        if action.path and any(p in action.path for p in self.exclude_paths):
            return RoEDecision(False, "path excluído pelo RoE")

        if action.impact.rank > self.max_impact.rank:
            return RoEDecision(
                False,
                f"classe de teste '{action.impact.label}' acima do autorizado "
                f"('{self.max_impact.label}')",
            )
        return RoEDecision(True)

    def check(self, action: Action) -> None:
        """Levanta :class:`RoEViolation` se a ação violar o RoE."""
        decision = self.evaluate(action)
        if not decision.allowed:
            raise RoEViolation(decision.reason or "ação viola o RoE")

    def to_dict(self) -> dict[str, Any]:
        """Serialização canônica (para ``digest`` e persistência)."""
        return {
            "engagement": self.engagement,
            "windows": [
                {
                    "weekdays": sorted(w.weekdays),
                    "start": w.start.isoformat(),
                    "end": w.end.isoformat(),
                }
                for w in self.windows
            ],
            "exclude_hosts": sorted(self.exclude_hosts),
            "exclude_ports": sorted(self.exclude_ports),
            "exclude_paths": sorted(self.exclude_paths),
            "max_impact": self.max_impact.value,
            "rate_limit": (
                None
                if self.rate_limit is None
                else {
                    "max_per_second": self.rate_limit.max_per_second,
                    "max_per_minute": self.rate_limit.max_per_minute,
                }
            ),
            "emergency_contacts": sorted(self.emergency_contacts),
        }

    def digest(self) -> str:
        """SHA-256 do RoE canônico — referenciável na trilha (§18.3) e autorização
        assinável (§18.4). Mesmo RoE ⇒ mesmo digest."""
        blob = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RulesOfEngagement:
        rl = data.get("rate_limit")
        return cls(
            engagement=str(data.get("engagement", "")),
            windows=[TimeWindow.from_dict(w) for w in data.get("windows", [])],
            exclude_hosts=[extract_host(str(h)) for h in data.get("exclude_hosts", [])],
            exclude_ports=frozenset(int(p) for p in data.get("exclude_ports", [])),
            exclude_paths=[str(p) for p in data.get("exclude_paths", [])],
            max_impact=ImpactClass.from_str(
                data.get("max_impact"), default=ImpactClass.ACTIVE_SAFE
            ),
            rate_limit=(
                None
                if not rl
                else RateLimit(
                    max_per_second=rl.get("max_per_second"),
                    max_per_minute=rl.get("max_per_minute"),
                )
            ),
            emergency_contacts=[str(c) for c in data.get("emergency_contacts", [])],
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> RulesOfEngagement:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("RoE inválido: raiz deve ser um mapa")
        return cls.from_dict(data)
