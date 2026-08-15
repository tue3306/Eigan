"""Execução segura de ferramenta externa — base do *runner* de um plugin.

Todo scanner externo (nmap, nuclei, httpx, ...) é encapsulado por um
:class:`BaseToolPlugin` que: verifica disponibilidade, monta argumentos de forma
segura (lista, nunca string concatenada / nunca ``shell=True``), executa com
timeout, captura a saída e delega o parse para o ``parser.py`` do plugin.

Regras de segurança do produto (inegociável §5): sempre lista de argumentos,
nunca shell, timeout obrigatório, saída tratada. Este módulo é a única porta por
onde um subprocess é disparado.

Os **metadados declarativos** (perspectivas, licença, capabilities, ...) NÃO
ficam aqui — vivem no ``metadata.yaml`` do plugin e são carregados como
:class:`~eigan.engine.plugin.PluginMetadata`. Isto separa *como executar*
(este arquivo) de *o que o plugin é* (metadados).
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..findings.schema import Finding


class ToolNotAvailable(Exception):
    """Ferramenta externa não encontrada no PATH nem no sandbox."""


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class BaseToolPlugin(ABC):
    """Runner: encapsula a execução segura de uma ferramenta e o parse da saída.

    Subclasses (em ``plugins/<cat>/<nome>/runner.py``) definem ``binary``,
    ``name``, ``build_args`` e ``parse``. Os metadados declarativos são anexados
    pelo registry via :attr:`metadata` — mas o runner funciona isolado (testes de
    parser) sem eles.
    """

    #: nome do binário no PATH
    binary: str = ""
    #: nome lógico da ferramenta (vai para ``source_tool`` do finding)
    name: str = ""
    #: timeout padrão em segundos
    default_timeout: int = 600
    #: alvo é passado via stdin em vez de argumento? (dnsx, httpx-PD)
    target_via_stdin: bool = False

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_args(self, target: str, **options) -> list[str]:
        """Monta a lista de argumentos (sem o binário). NUNCA retorne uma string
        única; cada token é um elemento da lista para evitar injeção de shell."""

    @abstractmethod
    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        """Converte a saída bruta em findings normalizados (delegado ao
        ``parser.py`` do plugin)."""

    def _run(
        self, args: list[str], timeout: int | None = None, stdin_data: str | None = None
    ) -> ToolResult:
        """Executa a ferramenta com segurança: lista de argumentos, ``shell=False``
        e timeout obrigatório.

        NOTA (sandbox): este é o modo "host". O caminho recomendado é rodar cada
        ferramenta em container efêmero (rede/escopo controlados); o runner
        permanece o mesmo, trocando apenas o executor. Ver ``docker/``.
        """
        if not self.available():
            raise ToolNotAvailable(
                f"'{self.binary}' não encontrado. Instale-o (veja `eigan doctor`) "
                "ou rode via sandbox Docker."
            )
        cmd = [self.binary, *args]
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_data,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",  # bytes inválidos da ferramenta NÃO podem derrubar o runner
                timeout=timeout or self.default_timeout,
                shell=False,  # explicitamente nunca shell
                check=False,
            )
            return ToolResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            # No timeout o stdout parcial pode vir como bytes (não passou pelo
            # decode text=True). Decodifica tolerante — a saída da ferramenta sob
            # teste não é confiável e bytes inválidos NÃO podem derrubar o runner.
            raw = exc.stdout
            stdout = (
                raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else (raw or "")
            )
            return ToolResult(
                exit_code=124,
                stdout=stdout,
                stderr="timeout",
                timed_out=True,
            )

    def safe_parse(self, result: ToolResult, target: str) -> list[Finding]:
        """Parse defensivo (§7.2): saída de ferramenta vem de um alvo **hostil** — a
        superfície de ataque mais direta do produto. Qualquer exceção do parser do
        plugin em entrada malformada é **contida** (retorna ``[]`` e loga), nunca
        derruba o scan. É o piso de robustez que TODO plugin herda (P6); o ``parse``
        específico pode ser endurecido por cima, mas o crash nunca vaza para o produto.
        """
        try:
            return self.parse(result, target)
        except Exception as exc:  # noqa: BLE001 — saída hostil não derruba o produto
            import logging

            logging.getLogger("eigan.parser").warning(
                "parser de '%s' falhou em saída malformada (contido, 0 findings): %s",
                self.name or self.binary,
                exc,
            )
            return []

    def scan(self, target: str, *, timeout: int | None = None, **options) -> list[Finding]:
        args = self.build_args(target, **options)
        stdin_data = f"{target}\n" if self.target_via_stdin else None
        result = self._run(args, timeout=timeout, stdin_data=stdin_data)
        return self.safe_parse(result, target)


# Compat: o nome anterior era ``BaseToolAdapter``. Mantido como alias para não
# quebrar imports externos; o nome canônico é ``BaseToolPlugin``.
BaseToolAdapter = BaseToolPlugin
