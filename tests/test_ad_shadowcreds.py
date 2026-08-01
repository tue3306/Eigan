"""Shadow Credentials Assessment (TIER X.8).

Falha antes / passa depois: msDS-KeyCredentialLink gravável por baixo privilégio é
sinalizado (crítico em objeto privilegiado); presença do atributo é sinalizada como
revisão; objeto seguro não gera nada; ordenação por severidade.
"""

from __future__ import annotations

from eigan.analysis.ad.shadowcreds import AdObjectKeyCred, assess_shadow_credentials
from eigan.findings.schema import Severity


def test_writable_keycredentiallink_is_high() -> None:
    obj = AdObjectKeyCred(name="user:bob", writable_by_low_priv=True)
    findings = assess_shadow_credentials([obj])
    assert [f.kind for f in findings] == ["shadow_credentials_writable"]
    assert findings[0].severity is Severity.HIGH


def test_writable_on_privileged_target_is_critical() -> None:
    obj = AdObjectKeyCred(name="user:admin", writable_by_low_priv=True, is_privileged_target=True)
    assert assess_shadow_credentials([obj])[0].severity is Severity.CRITICAL


def test_present_key_credential_flagged_for_review() -> None:
    obj = AdObjectKeyCred(name="user:svc", has_key_credential=True)
    findings = assess_shadow_credentials([obj])
    assert [f.kind for f in findings] == ["shadow_credentials_present"]
    assert findings[0].severity is Severity.MEDIUM


def test_safe_object_produces_nothing() -> None:
    assert assess_shadow_credentials([AdObjectKeyCred(name="user:ok")]) == []


def test_sorted_by_severity() -> None:
    objs = [
        AdObjectKeyCred(name="a", has_key_credential=True),  # MEDIUM
        AdObjectKeyCred(name="b", writable_by_low_priv=True, is_privileged_target=True),  # CRITICAL
    ]
    findings = assess_shadow_credentials(objs)
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].severity.rank >= findings[-1].severity.rank
