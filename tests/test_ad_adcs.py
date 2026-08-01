"""Classificação de ESC de AD CS (TIER X.5/X.6).

Falha antes / passa depois: cada classe ESC é sinalizada quando (e só quando) sua
condição de atributos está presente; templates seguros não geram nada; ordenação por
severidade. Só a partir de atributos coletados — nada fabricado.
"""

from __future__ import annotations

from eigan.analysis.ad.adcs import (
    CaConfiguration,
    CertificateTemplate,
    classify_adcs,
)
from eigan.findings.schema import Severity


def test_esc1_detected_only_when_all_conditions_hold() -> None:
    vuln = CertificateTemplate(
        name="UserAuth",
        client_authentication=True,
        enrollee_supplies_subject=True,
        low_privileged_enrollment=True,
    )
    findings = classify_adcs([vuln])
    assert [f.esc for f in findings] == ["ESC1"]
    assert findings[0].severity is Severity.CRITICAL

    # com aprovação de gerente, ESC1 não se aplica
    gated = CertificateTemplate(
        name="UserAuth",
        client_authentication=True,
        enrollee_supplies_subject=True,
        low_privileged_enrollment=True,
        requires_manager_approval=True,
    )
    assert classify_adcs([gated]) == []


def test_esc2_any_purpose() -> None:
    t = CertificateTemplate(name="AnyPurpose", any_purpose_eku=True, low_privileged_enrollment=True)
    assert [f.esc for f in classify_adcs([t])] == ["ESC2"]


def test_esc3_enrollment_agent() -> None:
    t = CertificateTemplate(name="Agent", enrollment_agent_eku=True, low_privileged_enrollment=True)
    assert [f.esc for f in classify_adcs([t])] == ["ESC3"]


def test_esc4_vulnerable_template_acl() -> None:
    t = CertificateTemplate(name="Weak", vulnerable_acl=True)
    assert [f.esc for f in classify_adcs([t])] == ["ESC4"]


def test_esc6_7_8_and_5_on_ca() -> None:
    ca = CaConfiguration(
        name="CORP-CA",
        editf_attributesubjectaltname2=True,  # ESC6
        vulnerable_acl=True,  # ESC7
        web_enrollment_http=True,  # ESC8 (sem channel binding)
        esc5_vulnerable_pki_acl=True,  # ESC5
    )
    escs = {f.esc for f in classify_adcs([], ca)}
    assert escs == {"ESC5", "ESC6", "ESC7", "ESC8"}


def test_esc8_mitigated_by_channel_binding() -> None:
    ca = CaConfiguration(name="CA", web_enrollment_http=True, enforces_channel_binding=True)
    assert classify_adcs([], ca) == []  # EPA/HTTPS mitiga o relay


def test_safe_template_and_ca_produce_nothing() -> None:
    safe_t = CertificateTemplate(name="Safe", client_authentication=True)  # sem SAN nem baixo priv
    safe_ca = CaConfiguration(name="CA")
    assert classify_adcs([safe_t], safe_ca) == []


def test_findings_sorted_by_severity() -> None:
    t_crit = CertificateTemplate(
        name="Crit",
        client_authentication=True,
        enrollee_supplies_subject=True,
        low_privileged_enrollment=True,
    )
    t_high = CertificateTemplate(name="High", vulnerable_acl=True)
    findings = classify_adcs([t_high, t_crit])
    assert findings[0].severity.rank >= findings[-1].severity.rank
    assert findings[0].esc == "ESC1"  # crítico primeiro
