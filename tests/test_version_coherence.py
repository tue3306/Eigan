"""Coerência de versão (§0.2): ``pyproject.toml`` é a fonte única de verdade.

Falha o build se ``pyproject.toml``, ``eigan.__version__``, o badge de versão do
README e a política de versões suportadas do ``SECURITY.md`` divergirem —
documentação que mente sobre a versão quebra o build (P1/P2). Ao subir a versão,
altere ``pyproject.toml`` e derive o resto; estes testes apontam o que ficou para
trás.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import eigan

_ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_package_version_matches_pyproject() -> None:
    assert eigan.__version__ == _pyproject_version(), (
        "eigan.__version__ divergiu de pyproject.toml [project].version "
        "(a fonte única de verdade da versão)"
    )


def test_readme_version_badge_matches_pyproject() -> None:
    version = _pyproject_version()
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    # o badge de versão codifica "versão" como "vers%C3%A3o-<version>-<cor>".
    assert f"vers%C3%A3o-{version}-" in readme, (
        f"o badge de versão do README não reflete a versão {version} do pyproject"
    )


def test_security_policy_references_current_version() -> None:
    version = _pyproject_version()
    security = (_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert version in security, (
        f"SECURITY.md não referencia a versão atual {version} — a política de "
        "versões suportadas ficou incoerente com o pyproject"
    )
