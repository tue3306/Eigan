"""Export para SIEM em CEF (§16.2).

Falha antes / passa depois: o cabeçalho CEF tem os 7 campos na ordem certa; a severidade
mapeia para 0–10; caracteres especiais são escapados conforme a spec; segredos são
redigidos; a saída é determinística (mesmos findings ⇒ mesma linha).
"""

from __future__ import annotations

from eigan import __version__
from eigan.findings.schema import Finding, Severity
from eigan.integrations.siem import finding_to_cef, to_cef


def _f(**kw) -> Finding:
    base = dict(
        title="SQLi", severity=Severity.HIGH, affected_asset="10.0.0.1", source_tool="nuclei"
    )
    base.update(kw)
    return Finding(**base)


def test_cef_header_structure_and_severity() -> None:
    line = finding_to_cef(_f(cwe="CWE-89", severity=Severity.CRITICAL))
    header = line.split("|")
    assert header[0] == "CEF:0"
    assert header[1] == "EIGAN"  # vendor
    assert header[2] == "EIGAN"  # product
    assert header[3] == __version__  # device version
    assert header[4] == "CWE-89"  # signature id
    assert header[5] == "SQLi"  # name
    assert header[6] == "9"  # critical → 9


def test_severity_mapping() -> None:
    ranks = {
        Severity.INFO: "0",
        Severity.LOW: "3",
        Severity.MEDIUM: "5",
        Severity.HIGH: "7",
        Severity.CRITICAL: "9",
    }
    for sev, cef in ranks.items():
        assert finding_to_cef(_f(severity=sev)).split("|")[6] == cef


def test_pipe_in_name_is_escaped() -> None:
    line = finding_to_cef(_f(title="a|b"))
    # o pipe do nome vira \| e não quebra a contagem de campos do cabeçalho
    assert "a\\|b" in line
    # antes da extensão há exatamente 7 campos de cabeçalho (separadores não-escapados)
    header_part = line.rsplit("|", 1)[0]  # remove a extensão
    # conta pipes não escapados no cabeçalho
    unescaped = header_part.replace("\\|", "")
    assert unescaped.count("|") == 6


def test_extension_escapes_equals() -> None:
    line = finding_to_cef(_f(affected_asset="a=b"))
    assert "dst=a\\=b" in line


def test_secret_is_redacted() -> None:
    line = finding_to_cef(_f(title="token=SECRETO", affected_asset="http://x?password=hunter2"))
    assert "SECRETO" not in line
    assert "hunter2" not in line


def test_deterministic_and_multiline() -> None:
    findings = [_f(cwe="CWE-89"), _f(affected_asset="10.0.0.2", cwe="CWE-79")]
    assert to_cef(findings) == to_cef(findings)  # determinístico
    assert to_cef(findings).count("\n") == 1  # duas linhas
    assert to_cef([]) == ""
