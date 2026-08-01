"""Shadow Credentials Assessment (TIER X.8) — implementação própria.

Identifica exposição a **Shadow Credentials**: quando um principal de baixo privilégio
pode escrever o atributo ``msDS-KeyCredentialLink`` de um objeto de AD, ele pode adicionar
uma credencial baseada em certificado e autenticar como o objeto (aquisição/persistência).
Também sinaliza `msDS-KeyCredentialLink` já presente onde não é esperado (indicador de
persistência para revisão). Implementação original (P7), decidindo só a partir do que foi
coletado (P1). Indicativo, para avaliação autorizada (P3).
"""

from __future__ import annotations

from dataclasses import dataclass

from ...findings.schema import Severity


@dataclass(frozen=True)
class AdObjectKeyCred:
    """Estado coletado do msDS-KeyCredentialLink de um objeto de AD."""

    name: str  # sam/DN do objeto (user/computer)
    writable_by_low_priv: bool = False  # baixo privilégio pode escrever o atributo
    has_key_credential: bool = False  # já há um KeyCredentialLink no objeto
    is_privileged_target: bool = False  # o objeto é privilegiado (ex.: membro de DA)


@dataclass(frozen=True)
class ShadowCredFinding:
    """Uma exposição de Shadow Credentials identificada."""

    kind: str
    severity: Severity
    target: str
    rationale: str


def _object_findings(o: AdObjectKeyCred) -> list[ShadowCredFinding]:
    out: list[ShadowCredFinding] = []
    if o.writable_by_low_priv:
        out.append(
            ShadowCredFinding(
                "shadow_credentials_writable",
                Severity.CRITICAL if o.is_privileged_target else Severity.HIGH,
                o.name,
                "msDS-KeyCredentialLink gravável por baixo privilégio"
                + (" em objeto privilegiado" if o.is_privileged_target else "")
                + " — aquisição via Shadow Credentials.",
            )
        )
    if o.has_key_credential:
        out.append(
            ShadowCredFinding(
                "shadow_credentials_present",
                Severity.MEDIUM,
                o.name,
                "msDS-KeyCredentialLink presente — revisar (possível persistência por "
                "certificado).",
            )
        )
    return out


def assess_shadow_credentials(objects: list[AdObjectKeyCred]) -> list[ShadowCredFinding]:
    """Avalia os objetos e devolve as exposições de Shadow Credentials, por severidade."""
    findings: list[ShadowCredFinding] = []
    for obj in objects:
        findings.extend(_object_findings(obj))
    findings.sort(key=lambda f: (-f.severity.rank, f.kind, f.target))
    return findings
