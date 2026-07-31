"""Parser do nmap-nse: elementos ``<script>`` do XML do nmap → findings.

Lê os resultados da NSE (``<port>/<script>`` e ``<hostscript>/<script>``) do XML
nativo (-oX -, https://nmap.org/book/nmap-dtd.html). Severidade por heurística
NOSSA de exposição (VULNERABLE → alta); nenhum CVSS é fabricado (§3.1) — se o
script cita um CVE-XXXX, ele entra como referência textual, marcada para
enriquecimento por fonte oficial.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "nmap-nse"
_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_VULNERABLE = re.compile(r"\bVULNERABLE\b|State:\s*VULNERABLE", re.IGNORECASE)


def _severity(script_id: str, output: str) -> Severity:
    if _VULNERABLE.search(output):
        return Severity.HIGH
    if script_id.startswith("smb-vuln") or "vuln" in script_id:
        return Severity.MEDIUM
    return Severity.INFO


def _finding(host: str, portid: str | None, script_id: str, output: str) -> Finding:
    asset = f"{host}:{portid}" if portid else host
    cves = sorted(set(m.upper() for m in _CVE.findall(output)))
    refs = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves]
    refs.append("https://nmap.org/book/nse.html")
    desc = output.strip()[:800]
    if cves:
        # anti-invenção: o CVE é só referência do script; não afirmamos CVSS aqui.
        desc += (
            f"\n\nCVE(s) citado(s) pelo script (UNVERIFIED até fonte oficial): {', '.join(cves)}"
        )
    return Finding(
        title=f"NSE {script_id} em {asset}",
        severity=_severity(script_id, output),
        affected_asset=asset,
        source_tool=TOOL,
        description=desc or f"Resultado do script NSE {script_id}.",
        evidence=output.strip()[:500],
        confidence=Confidence.FIRM if _VULNERABLE.search(output) else Confidence.TENTATIVE,
        attack_technique="T1046",  # Network Service Discovery
        references=refs,
    )


def parse(result: ToolResult, target: str) -> list[Finding]:
    if not result.stdout.strip():
        return []
    try:
        # Entrada = XML do nosso `nmap -oX` (subprocess controlado, sem shell). O
        # hardening com defusedxml está planejado no TIER 7.2 (fuzzing de parsers).
        root = ET.fromstring(result.stdout)  # nosec B314
    except ET.ParseError:
        return []

    findings: list[Finding] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else target
        # scripts por porta
        for port in host.findall(".//port"):
            portid = port.get("portid")
            for script in port.findall("script"):
                sid = script.get("id", "script")
                out = script.get("output", "")
                findings.append(_finding(addr, portid, sid, out))
        # scripts de host (hostscript)
        for hs in host.findall("hostscript/script"):
            findings.append(_finding(addr, None, hs.get("id", "script"), hs.get("output", "")))
    return findings
