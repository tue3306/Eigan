#!/usr/bin/env python3
"""EIGAN — launcher único (Missão 1: "unzip e um comando").

    git clone …  &&  cd ScanVuln  &&  python3 eigan.py

Este arquivo usa **apenas a stdlib** e é o único ponto de entrada que um usuário
precisa conhecer. Num clone limpo, sem nada instalado, ele:

  1. confere Python ≥ 3.11 (senão, aponta o download oficial do seu SO);
  2. cria um ambiente virtual em ``.venv``;
  3. instala o EIGAN e dependências (``.[pdf,tui]`` por padrão; ``.[ai]`` /
     ``.[dev]`` sob demanda);
  4. gera ``.env`` a partir de ``.env.example`` e prepara diretórios de config;
  5. reexecuta a si mesmo dentro do venv e abre o **menu interativo**.

Se o pacote já é importável (venv ativo, ``pip install -e .``, Docker), pula o
bootstrap. Argumentos são repassados à CLI:

    python3 eigan.py                 # menu interativo (Novo Scan = wizard)
    python3 eigan.py scan alvo.com   # scan direto (headless/CI)
    python3 eigan.py doctor          # diagnóstico  (--install provisiona ferramentas)

Uso autorizado apenas: só escaneie alvos que você possui ou tem permissão
escrita para testar.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
_BOOTSTRAP_FLAG = "EIGAN_BOOTSTRAPPED"
#: Extras instalados por padrão: PDF (relatório) + TUI (interface full-screen).
_DEFAULT_EXTRAS = ("pdf", "tui")

_LAUNCHER_FLAGS = {
    "--with-tools": "with_tools",
    "--with-ai": "with_ai",
    "--reinstall": "reinstall",
    "--no-venv": "no_venv",
    "--serve": "serve",
    "--dev": "dev",
}


# --------------------------------------------------------------------------- #
# Descoberta de ambiente (stdlib puro — roda antes de qualquer instalação).
# --------------------------------------------------------------------------- #
def _deshadow() -> None:
    """Impede que este script (``ROOT/eigan.py``) sombreie o pacote instalado
    ``eigan`` (mesmo nome). Remove o diretório do script de ``sys.path`` — o
    módulo já carregado como ``__main__`` continua válido. Idempotente."""
    root = str(ROOT)
    sys.path[:] = [p for p in sys.path if p not in ("", ".", root)]


def venv_python(venv_dir: Path = VENV_DIR) -> Path:
    """Caminho do interpretador dentro de um venv (POSIX/Windows)."""
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def package_importable() -> bool:
    """True se o **pacote** ``eigan`` (não este script) é importável agora."""
    import importlib.util

    try:
        # O submódulo evita casar com o script (que não é um pacote).
        return importlib.util.find_spec("eigan.cli.main") is not None
    except (ImportError, ValueError):
        return False


def _python_download_url() -> str:
    if sys.platform.startswith("win"):
        return "https://www.python.org/downloads/windows/"
    if sys.platform == "darwin":
        return "https://www.python.org/downloads/macos/"
    return "https://www.python.org/downloads/ (ou o gerenciador da sua distro: apt/dnf/pacman)"


def _check_python() -> bool:
    """Exige Python ≥ 3.11 com mensagem acionável (não stack trace)."""
    if sys.version_info >= (3, 11):
        return True
    have = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(f"EIGAN requer Python 3.11+ — você tem {have}.")
    print(f"Baixe/atualize: {_python_download_url()}")
    print("Depois rode de novo: python3 eigan.py")
    return False


# --------------------------------------------------------------------------- #
# Autoconfig de 1ª execução.
# --------------------------------------------------------------------------- #
def ensure_env_file() -> None:
    """Cria ``.env`` a partir de ``.env.example`` se ainda não existir."""
    env, example = ROOT / ".env", ROOT / ".env.example"
    if example.exists() and not env.exists():
        try:
            shutil.copyfile(example, env)
            print("· .env criado a partir de .env.example")
        except OSError as exc:
            print(f"· não foi possível criar .env: {exc}")


def _config_dir() -> Path:
    base = os.environ.get("EIGAN_CONFIG_DIR") or os.path.join(
        os.path.expanduser("~"), ".config", "eigan"
    )
    return Path(base)


def ensure_dirs() -> None:
    """Prepara o diretório de configuração/estado (termo, cache de feeds)."""
    try:
        _config_dir().mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Provisão do ambiente (venv + instalação).
# --------------------------------------------------------------------------- #
def _install_spec(opts: dict[str, bool]) -> str:
    extras = list(_DEFAULT_EXTRAS)
    if opts.get("with_ai"):
        extras.append("ai")
    if opts.get("dev"):
        extras.append("dev")
    return f".[{','.join(extras)}]"


def create_venv() -> bool:
    print("· Criando ambiente virtual em .venv (primeira execução)…")
    try:
        import venv

        venv.EnvBuilder(with_pip=True, upgrade_deps=False).create(str(VENV_DIR))
        return True
    except Exception as exc:  # noqa: BLE001 — acionável (ex.: falta o módulo venv)
        print(f"  Falha ao criar o venv: {exc}")
        print("  Instale o módulo venv (Debian/Ubuntu/Kali): sudo apt install python3-venv")
        return False


def _venv_has_package(py: Path) -> bool:
    # `-I` isola o interpretador (ignora cwd e PYTHON*), evitando que o script
    # ROOT/eigan.py seja importado no lugar do pacote.
    result = subprocess.run([str(py), "-I", "-c", "import eigan.cli.main"], capture_output=True)
    return result.returncode == 0


def _pip_install(py: Path, spec: str) -> bool:
    result = subprocess.run([str(py), "-m", "pip", "install", "-q", "-e", spec], cwd=str(ROOT))
    return result.returncode == 0


def install_package(py: Path, opts: dict[str, bool]) -> bool:
    subprocess.run([str(py), "-m", "pip", "install", "-q", "--upgrade", "pip"], cwd=str(ROOT))
    print("· Instalando o EIGAN e dependências…")
    for candidate in (_install_spec(opts), "."):
        if _pip_install(py, candidate):
            return True
        print(f"  ('{candidate}' não instalou; tentando alternativa mais simples…)")
    print("  Falha ao instalar as dependências. Verifique a conexão e tente de novo.")
    return False


def _pip_install_current(opts: dict[str, bool]) -> bool:
    """Instala no interpretador atual (--no-venv). Pode esbarrar em PEP 668."""
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "--upgrade", "pip"], cwd=str(ROOT)
    )
    print("· Instalando o EIGAN no ambiente atual (--no-venv)…")
    for candidate in (_install_spec(opts), "."):
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "-e", candidate], cwd=str(ROOT)
        )
        if result.returncode == 0:
            return True
    print("  Falha ao instalar. Verifique conexão/permissões (ambiente gerenciado? PEP 668).")
    return False


def ensure_environment(opts: dict[str, bool]) -> Path | None:
    """Garante um venv com o pacote instalado. Retorna o python do venv ou None."""
    py = venv_python()
    if not py.exists():
        if not create_venv():
            return None
        py = venv_python()
    if not _venv_has_package(py):
        if not install_package(py, opts):
            return None
    return py


def _remove_venv() -> None:
    if not VENV_DIR.exists():
        return
    try:
        running_here = Path(sys.prefix).resolve() == VENV_DIR.resolve()
    except OSError:
        running_here = False
    if running_here:
        print("· --reinstall ignorado: rodando de dentro do próprio .venv.")
        return
    print("· Removendo .venv (--reinstall)…")
    shutil.rmtree(VENV_DIR, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Extras de fase B (dentro do ambiente pronto).
# --------------------------------------------------------------------------- #
def _pdf_marker() -> Path:
    return _config_dir() / "pdf_notice_shown"


def _pdf_notice() -> None:
    """Avisa uma única vez se o PDF estiver indisponível (degrada para HTML)."""
    try:
        from eigan.report.pdf_support import pdf_status
    except Exception:  # noqa: BLE001 — pacote deve importar aqui; se não, silencie
        return
    ok, detail = pdf_status()
    if ok:
        return
    marker = _pdf_marker()
    if marker.exists():
        return
    print(f"· PDF indisponível — relatórios sairão em HTML. {detail}")
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("shown\n")
    except OSError:
        pass


def _ensure_extra_installed(extra: str) -> None:
    print(f"· Garantindo o extra [{extra}]…")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "-e", f".[{extra}]"], cwd=str(ROOT)
    )


def _print_ai_hint() -> None:
    print("\nIA (obrigatória — o EIGAN é um agente de IA): defina UM provedor e reinicie:")
    print("  ANTHROPIC_API_KEY=…   (ou OPENAI_API_KEY / GOOGLE_API_KEY)")
    print("  OLLAMA_HOST=http://localhost:11434   (local, sem chave e sem custo)")
    print("Sem um provedor, o scan é recusado. Ollama roda 100% local — nada sai da máquina.\n")


# --------------------------------------------------------------------------- #
# Parsing de flags do launcher + ajuda + hand-off para a CLI.
# --------------------------------------------------------------------------- #
def _parse_launcher_flags(argv: list[str]) -> tuple[dict[str, bool], list[str]]:
    opts: dict[str, bool] = dict.fromkeys(_LAUNCHER_FLAGS.values(), False)
    opts["help"] = False
    cli_args: list[str] = []
    for arg in argv:
        if arg in _LAUNCHER_FLAGS:
            opts[_LAUNCHER_FLAGS[arg]] = True
        elif arg in ("-h", "--help") and not cli_args:
            # --help como 1º token = ajuda do launcher (rápida, sem bootstrap);
            # `eigan.py doctor --help` etc. seguem para a CLI.
            opts["help"] = True
        else:
            cli_args.append(arg)
    return opts, cli_args


def _print_launcher_help() -> None:
    print(__doc__ or "")
    print("Flags do launcher:")
    print("  --with-tools   provisiona as ferramentas reais (doctor --install, com confirmação)")
    print("  --with-ai      instala o extra de IA e mostra como configurar a chave")
    print("  --serve        sobe o dashboard e abre o navegador")
    print("  --reinstall    recria o .venv do zero")
    print("  --no-venv      usa o interpretador atual (não cria .venv)")
    print("  --dev          inclui as dependências de desenvolvimento")
    print("  -h, --help     esta ajuda")
    print("\nQualquer outro argumento vai para a CLI:")
    print("  python3 eigan.py                 # menu interativo (Novo Scan = wizard)")
    print("  python3 eigan.py scan ALVO       # scan direto (headless/CI)")
    print("  python3 eigan.py doctor          # diagnóstico (--install provisiona ferramentas)")
    print("  python3 eigan.py serve           # dashboard web")
    print("  python3 eigan.py <cmd> --help    # ajuda detalhada de um comando da CLI")


def run_app(argv: list[str]) -> int:
    """Entrega o controle à CLI do pacote instalado (menu quando sem argumentos)."""
    from eigan.cli.main import main as cli_main

    sys.argv = ["eigan", *argv]
    try:
        cli_main()
    except SystemExit as exc:  # click chama sys.exit; propaga o código
        return int(exc.code or 0)
    return 0


def _run_phase_b(opts: dict[str, bool], cli_args: list[str]) -> int:
    """Ambiente pronto: extras opcionais e, então, a CLI."""
    _pdf_notice()
    if opts["with_ai"]:
        _ensure_extra_installed("ai")
        _print_ai_hint()
    if opts["with_tools"]:
        run_app(["doctor", "--install"])
    if opts["serve"] and not cli_args:
        cli_args = ["serve", "--open"]
    return run_app(cli_args)


def _reexec(py: Path, argv: list[str]) -> int:
    env = {**os.environ, _BOOTSTRAP_FLAG: "1"}
    print("· Ambiente pronto — iniciando o EIGAN…\n")
    return subprocess.run([str(py), str(ROOT / "eigan.py"), *argv], env=env).returncode


def _fail_actionable() -> None:
    print("\nNão foi possível preparar o ambiente automaticamente. Faça manualmente:")
    print("  python3 -m venv .venv && . .venv/bin/activate")
    print("  pip install -e '.[pdf,tui]'")
    print("  eigan")


def main(argv: list[str]) -> int:
    _deshadow()
    opts, cli_args = _parse_launcher_flags(argv)

    if opts["help"]:
        _print_launcher_help()
        return 0

    if not _check_python():
        return 1

    ensure_env_file()
    ensure_dirs()

    if opts["reinstall"] and not os.environ.get(_BOOTSTRAP_FLAG):
        _remove_venv()

    # Já importável (dev/instalado) e sem pedir reinstalação: usa direto.
    if package_importable() and not opts["reinstall"]:
        return _run_phase_b(opts, cli_args)

    # Precisamos instalar: no interpretador atual (--no-venv) ou num .venv.
    if opts["no_venv"]:
        if not package_importable() and not _pip_install_current(opts):
            return 1
        return _run_phase_b(opts, cli_args)

    if os.environ.get(_BOOTSTRAP_FLAG):
        # Já reexecutamos para dentro do venv.
        if package_importable():
            return _run_phase_b(opts, cli_args)
        _fail_actionable()
        return 1

    py = ensure_environment(opts)
    if py is None:
        return 1
    return _reexec(py, argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
