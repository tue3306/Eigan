"""Parser do nmap: XML nativo (-oX -) → findings de porta/serviço abertos.

Faz o parse do XML documentado (https://nmap.org/book/nmap-dtd.html) em vez de
raspar texto. Só portas ``open`` viram finding.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "nmap"


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    if not result.stdout.strip():
        return findings
    try:
        # Entrada = XML do nosso `nmap -oX` (subprocess controlado, sem shell). O
        # hardening com defusedxml está planejado no TIER 7.2 (fuzzing de parsers).
        root = ET.fromstring(result.stdout)  # nosec B314
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else target
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            banner = f"{product} {version}".strip()

            findings.append(
                Finding(
                    title=f"Porta aberta {portid}/{proto} ({svc_name})",
                    severity=Severity.INFO,
                    affected_asset=f"{addr}:{portid}",
                    source_tool=TOOL,
                    description=(
                        f"Serviço '{svc_name}' exposto em {addr}:{portid}/{proto}."
                        + (f" Banner: {banner}." if banner else "")
                    ),
                    evidence=result.stdout[:2000],
                    # versão detectada NÃO é confirmada contra base de CVE aqui:
                    confidence=Confidence.FIRM if banner else Confidence.TENTATIVE,
                    attack_technique="T1046",  # Network Service Discovery (MITRE ATT&CK)
                    references=["https://attack.mitre.org/techniques/T1046/"],
                )
            )
    return findings
