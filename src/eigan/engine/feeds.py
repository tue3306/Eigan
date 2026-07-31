"""Feeds de inteligência de vulnerabilidade — EPSS (FIRST.org) e KEV (CISA).

Regra inegociável (§5 / ADR-0002): estes números são **fato factual** e por isso
vêm **sempre** da fonte oficial, com cache; **nunca** de memória ou fabricação.
Se o feed não foi obtido, o dado sai ``UNVERIFIED`` (o :class:`RiskScorer` usa só
o que é verificável).

Fontes confirmadas (schema verificado em runtime, não assumido):
  - KEV : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
          → { catalogVersion, dateReleased, count, vulnerabilities:[{cveID,...}] }
  - EPSS: https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2
          → { data:[{cve, epss, percentile, date}] }  (batch por vírgula)

Cache fora do repositório (``$EIGAN_CACHE_DIR`` ou ``~/.cache/eigan``).
Rede só é tocada em :meth:`FeedCache.update_kev` / :meth:`update_epss`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("eigan.feeds")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
_EPSS_BATCH = 80  # CVEs por requisição (limita o tamanho da URL)


def default_cache_dir() -> Path:
    env = os.getenv("EIGAN_CACHE_DIR")
    base = Path(env) if env else Path.home() / ".cache" / "eigan"
    return base / "feeds"


def _http_get(url: str, timeout: int = 30) -> bytes:
    """GET simples com timeout (stdlib, sem dependência externa). Valida esquema
    para evitar file:// e afins (menor privilégio)."""
    if not url.lower().startswith("https://"):
        raise ValueError(f"URL de feed deve ser HTTPS: {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": "EIGAN/feeds"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — esquema validado a HTTPS acima
        return resp.read()


@dataclass
class FeedCache:
    """Cache local dos feeds. Carregado do disco; atualizado só sob demanda."""

    cache_dir: Path = field(default_factory=default_cache_dir)
    kev_cves: set[str] | None = None  # None = feed KEV nunca obtido (UNVERIFIED)
    kev_meta: dict = field(default_factory=dict)
    epss_scores: dict[str, float] = field(default_factory=dict)
    epss_meta: dict = field(default_factory=dict)

    # ── persistência ──────────────────────────────────────────────────────────
    @property
    def _kev_path(self) -> Path:
        return self.cache_dir / "kev.json"

    @property
    def _epss_path(self) -> Path:
        return self.cache_dir / "epss.json"

    @classmethod
    def load(cls, cache_dir: Path | None = None) -> "FeedCache":
        c = cls(cache_dir=cache_dir or default_cache_dir())
        if c._kev_path.exists():
            try:
                data = json.loads(c._kev_path.read_text())
                c.kev_cves = {s.upper() for s in data.get("cves", [])}
                c.kev_meta = data.get("meta", {})
            # AttributeError/TypeError: JSON válido de tipo errado (ex.: lista no
            # lugar de objeto) — trata como cache ilegível em vez de derrubar o scan.
            except (json.JSONDecodeError, OSError, AttributeError, TypeError) as exc:
                log.warning("cache KEV ilegível: %s", exc)
                c.kev_cves, c.kev_meta = set(), {}
        if c._epss_path.exists():
            try:
                data = json.loads(c._epss_path.read_text())
                c.epss_scores = {k.upper(): float(v) for k, v in data.get("scores", {}).items()}
                c.epss_meta = data.get("meta", {})
            except (json.JSONDecodeError, OSError, ValueError, AttributeError, TypeError) as exc:
                log.warning("cache EPSS ilegível: %s", exc)
                c.epss_scores, c.epss_meta = {}, {}
        return c

    def _save_kev(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._kev_path.write_text(
            json.dumps({"meta": self.kev_meta, "cves": sorted(self.kev_cves or [])}, indent=0)
        )

    def _save_epss(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._epss_path.write_text(json.dumps({"meta": self.epss_meta, "scores": self.epss_scores}))

    # ── atualização (rede) ──────────────────────────────────────────────────────
    def update_kev(self, getter=_http_get) -> dict:
        """Baixa o catálogo KEV completo e cacheia. Integridade por sha256."""
        raw = getter(KEV_URL)
        digest = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw)
        cves = [str(v["cveID"]).upper() for v in data.get("vulnerabilities", []) if v.get("cveID")]
        self.kev_cves = set(cves)
        self.kev_meta = {
            "source": KEV_URL,
            "catalogVersion": data.get("catalogVersion", ""),
            "dateReleased": data.get("dateReleased", ""),
            "count": len(cves),
            "sha256": digest,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_kev()
        return self.kev_meta

    def update_epss(self, cves: list[str], getter=_http_get) -> dict:
        """Consulta EPSS (FIRST.org) para os CVEs dados e mescla no cache.

        Só busca os CVEs ainda não cacheados. Retorna o meta com a data do feed.
        """
        wanted = sorted({c.upper() for c in cves if c})
        missing = [c for c in wanted if c not in self.epss_scores]
        feed_date = self.epss_meta.get("date", "")
        for i in range(0, len(missing), _EPSS_BATCH):
            batch = missing[i : i + _EPSS_BATCH]
            url = f"{EPSS_API}?cve={','.join(batch)}"
            try:
                payload = json.loads(getter(url))
            except (OSError, ValueError) as exc:  # rede/parse: não fabrica, deixa UNVERIFIED
                log.warning("EPSS indisponível para lote: %s", exc)
                continue
            for row in payload.get("data", []):
                cve = str(row.get("cve", "")).upper()
                try:
                    self.epss_scores[cve] = float(row.get("epss"))
                except (TypeError, ValueError):
                    continue
                feed_date = row.get("date", feed_date)
        self.epss_meta = {
            "source": EPSS_API,
            "date": feed_date,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "count": len(self.epss_scores),
        }
        self._save_epss()
        return self.epss_meta

    # ── consulta (offline) ───────────────────────────────────────────────────────
    @property
    def kev_available(self) -> bool:
        return self.kev_cves is not None

    def kev_date(self) -> str:
        return str(self.kev_meta.get("dateReleased") or self.kev_meta.get("catalogVersion") or "")

    def epss_date(self) -> str:
        return str(self.epss_meta.get("date", ""))
