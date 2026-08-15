"""Runner do httpx (ProjectDiscovery) — probe web + tech-detect.

Guard de identidade (§5 na prática): existe um binário homônimo — o cliente HTTP
``httpx`` do Python. O runner **resolve** qual ``httpx`` no sistema é o da
ProjectDiscovery (o web prober), mesmo quando o homônimo do Python está ANTES no
PATH (caso comum: ``/usr/bin/httpx`` do pip sombreia ``~/go/bin/httpx``). Testa
todos os candidatos e usa o primeiro que se identifica como PD; se nenhum for,
o plugin se declara indisponível (é pulado, sem emitir dado inventado).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class HttpxRunner(BaseToolPlugin):
    binary = "httpx"
    name = "httpx"

    #: caminho resolvido do httpx-PD (cache de classe). None = ainda não procurado;
    #: "" = procurado e nenhum candidato é o da ProjectDiscovery.
    _resolved: str | None = None

    def _candidates(self) -> list[str]:
        """Todos os ``httpx`` executáveis: cada dir do PATH (na ordem) + locais
        comuns de instalação Go (onde ``go install`` / ``pdtm`` colocam o binário)."""
        seen: set[str] = set()
        out: list[str] = []
        home = Path.home()
        dirs = os.environ.get("PATH", "").split(os.pathsep) + [
            str(home / "go" / "bin"),
            str(home / ".local" / "bin"),
            "/usr/local/bin",
            "/root/go/bin",
        ]
        names = ("httpx", "httpx.exe") if os.name == "nt" else ("httpx",)
        for d in dirs:
            if not d:
                continue
            for name in names:
                p = os.path.join(d, name)
                if p not in seen and os.path.isfile(p) and os.access(p, os.X_OK):
                    seen.add(p)
                    out.append(p)
        return out

    def _pd_binary(self) -> str | None:
        """Resolve (e cacheia) o caminho do httpx da ProjectDiscovery, mesmo que um
        homônimo esteja antes no PATH."""
        if HttpxRunner._resolved is not None:
            return HttpxRunner._resolved or None
        for cand in self._candidates():
            if self._is_projectdiscovery(cand):
                HttpxRunner._resolved = cand
                return cand
        HttpxRunner._resolved = ""  # procurado, nada é PD
        return None

    def available(self) -> bool:
        path = self._pd_binary()
        if path is None:
            return False
        # execução (BaseToolPlugin._run) usa self.binary → aponta para o PD resolvido,
        # não para o homônimo do Python que estava antes no PATH.
        self.binary = path
        return True

    @staticmethod
    def _is_projectdiscovery(path: str) -> bool:
        """Confirma que ``path`` é o httpx da ProjectDiscovery e não o cliente HTTP
        homônimo do Python (marcadores exclusivos do PD, ausentes no do Python)."""
        try:
            out = subprocess.run(
                [path, "-h"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                shell=False,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            return False
        blob = (out.stdout + out.stderr).lower()
        return "tech-detect" in blob or "projectdiscovery" in blob or "-td," in blob

    def build_args(self, target: str, *, rate_limit: int = 150, **_) -> list[str]:
        return [
            "-u",
            target,
            "-json",
            "-silent",
            "-td",
            "-title",
            "-status-code",
            "-rate-limit",
            str(int(rate_limit)),
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
