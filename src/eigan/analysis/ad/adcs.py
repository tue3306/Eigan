"""Active Directory Certificate Services — classificação de ESC (TIER X.5/X.6).

Dado o que a coleta autorizada obteve sobre **templates de certificado** e a **CA**,
classifica as principais configurações inseguras de AD CS (ESC1–ESC8). As condições são
**conceitos padrão da indústria** de segurança de AD CS; a **implementação é própria**
(P7) e opera só sobre atributos coletados — nada é fabricado (P1). É análise indicativa,
para avaliação autorizada (P3): sinaliza a condição, não afirma exploração.

Modelo mínimo e honesto: cada classe ESC tem uma condição decidível a partir de atributos
de template/CA. Onde a decisão exige contexto externo (ACLs de objetos de PKI mais amplos
— ESC5), o sinal é um atributo explícito fornecido pela coleta, não uma suposição.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...findings.schema import Severity


@dataclass(frozen=True)
class CertificateTemplate:
    """Atributos coletados de um template de certificado relevantes a ESC."""

    name: str
    client_authentication: bool = False  # EKU permite autenticação (Client Auth/PKINIT/…)
    enrollee_supplies_subject: bool = False  # requerente escolhe o subject/SAN
    any_purpose_eku: bool = False  # EKU "Any Purpose"
    no_eku: bool = False  # sem EKU (equivale a subordinate CA)
    enrollment_agent_eku: bool = False  # EKU Certificate Request Agent
    requires_manager_approval: bool = False  # aprovação de gerente exigida
    authorized_signatures_required: int = 0  # assinaturas RA exigidas
    low_privileged_enrollment: bool = False  # principais de baixo privilégio podem enrolar
    vulnerable_acl: bool = False  # baixo privilégio pode escrever/possuir o template


@dataclass(frozen=True)
class CaConfiguration:
    """Atributos coletados da CA relevantes a ESC."""

    name: str
    editf_attributesubjectaltname2: bool = False  # ESC6: qualquer requerente adiciona SAN
    vulnerable_acl: bool = False  # ESC7: baixo privilégio com ManageCA/ManageCertificates
    web_enrollment_http: bool = False  # endpoint de web enrollment sobre HTTP
    enforces_channel_binding: bool = False  # EPA/HTTPS mitigando relay
    esc5_vulnerable_pki_acl: bool = False  # ACL perigosa em objeto de PKI (contexto externo)


@dataclass(frozen=True)
class EscFinding:
    """Uma condição ESC identificada, com alvo e justificativa."""

    esc: str  # "ESC1" … "ESC8"
    severity: Severity
    target: str  # nome do template ou da CA
    title: str
    rationale: str
    references: list[str] = field(default_factory=list)


def _template_findings(t: CertificateTemplate) -> list[EscFinding]:
    out: list[EscFinding] = []
    no_gate = not t.requires_manager_approval and t.authorized_signatures_required == 0

    if (
        t.client_authentication
        and t.enrollee_supplies_subject
        and t.low_privileged_enrollment
        and no_gate
    ):
        out.append(
            EscFinding(
                "ESC1",
                Severity.CRITICAL,
                t.name,
                "Template permite SAN arbitrário com autenticação a baixo privilégio",
                "EKU de autenticação + enrollee supplies subject + enrolamento por baixo "
                "privilégio, sem aprovação de gerente nem assinaturas autorizadas.",
                ["AD CS ESC1"],
            )
        )
    if (t.any_purpose_eku or t.no_eku) and t.low_privileged_enrollment and no_gate:
        out.append(
            EscFinding(
                "ESC2",
                Severity.CRITICAL,
                t.name,
                "Template Any-Purpose/sem-EKU enrolável por baixo privilégio",
                "EKU Any Purpose (ou ausência de EKU) com enrolamento por baixo privilégio "
                "e sem gate — certificado utilizável para qualquer fim.",
                ["AD CS ESC2"],
            )
        )
    if t.enrollment_agent_eku and t.low_privileged_enrollment and not t.requires_manager_approval:
        out.append(
            EscFinding(
                "ESC3",
                Severity.HIGH,
                t.name,
                "Template com EKU de Enrollment Agent enrolável por baixo privilégio",
                "Certificate Request Agent enrolável por baixo privilégio permite requerer "
                "em nome de outros principais.",
                ["AD CS ESC3"],
            )
        )
    if t.vulnerable_acl:
        out.append(
            EscFinding(
                "ESC4",
                Severity.HIGH,
                t.name,
                "ACL do template permite modificação por baixo privilégio",
                "Escrita/posse do objeto de template por baixo privilégio permite torná-lo "
                "vulnerável (ex.: reconfigurar como ESC1).",
                ["AD CS ESC4"],
            )
        )
    return out


def _ca_findings(ca: CaConfiguration) -> list[EscFinding]:
    out: list[EscFinding] = []
    if ca.esc5_vulnerable_pki_acl:
        out.append(
            EscFinding(
                "ESC5",
                Severity.HIGH,
                ca.name,
                "ACL perigosa em objeto de PKI",
                "Objeto relacionado à PKI (ex.: container/CA no AD) com ACL que permite "
                "controle por baixo privilégio.",
                ["AD CS ESC5"],
            )
        )
    if ca.editf_attributesubjectaltname2:
        out.append(
            EscFinding(
                "ESC6",
                Severity.CRITICAL,
                ca.name,
                "CA com EDITF_ATTRIBUTESUBJECTALTNAME2 habilitado",
                "A CA aceita SAN arbitrário em qualquer requisição — SAN de qualquer "
                "principal, independente do template.",
                ["AD CS ESC6"],
            )
        )
    if ca.vulnerable_acl:
        out.append(
            EscFinding(
                "ESC7",
                Severity.HIGH,
                ca.name,
                "ACL da CA permite ManageCA/ManageCertificates por baixo privilégio",
                "Direitos administrativos da CA concedidos a baixo privilégio permitem "
                "aprovar requisições ou alterar a configuração da CA.",
                ["AD CS ESC7"],
            )
        )
    if ca.web_enrollment_http and not ca.enforces_channel_binding:
        out.append(
            EscFinding(
                "ESC8",
                Severity.HIGH,
                ca.name,
                "Web enrollment sem proteção contra NTLM relay",
                "Endpoint de web enrollment sobre HTTP sem channel binding/EPA — exposto a "
                "NTLM relay para requisição de certificado.",
                ["AD CS ESC8"],
            )
        )
    return out


def classify_adcs(
    templates: list[CertificateTemplate], ca: CaConfiguration | None = None
) -> list[EscFinding]:
    """Classifica as condições ESC dos templates e da CA. Ordenado por severidade."""
    findings: list[EscFinding] = []
    for template in templates:
        findings.extend(_template_findings(template))
    if ca is not None:
        findings.extend(_ca_findings(ca))
    findings.sort(key=lambda f: (-f.severity.rank, f.esc, f.target))
    return findings
