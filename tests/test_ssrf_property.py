"""Property-based do guard SSRF (§7.1): representações exóticas não furam o bloqueio.

Bugs de SSRF vivem em representações exóticas de IP/host. Aqui o hypothesis gera
milhares de entradas e verifica invariantes universais do guard.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eigan.security.ssrf import SsrfError, ip_category, is_metadata_literal, screen_ip


@given(s=st.text(max_size=200))
@settings(max_examples=300, deadline=None)
def test_is_metadata_literal_never_crashes(s: str) -> None:
    # Qualquer string (inclusive lixo/controle) → bool, nunca exceção.
    assert isinstance(is_metadata_literal(s), bool)


@given(ip=st.ip_addresses())
@settings(max_examples=400, deadline=None)
def test_screen_ip_invariants_by_category(ip) -> None:
    cat = ip_category(str(ip))
    if cat == "metadata":
        # Metadata é bloqueado SEMPRE — inclusive em assumed-breach (allow_private=True).
        with pytest.raises(SsrfError):
            screen_ip(str(ip), allow_private=True)
    elif cat == "public":
        screen_ip(str(ip), allow_private=False)  # público nunca bloqueia
        screen_ip(str(ip), allow_private=True)
    else:  # loopback | link-local | private | reserved
        with pytest.raises(SsrfError):
            screen_ip(str(ip), allow_private=False)  # bloqueado no modo externo
        screen_ip(str(ip), allow_private=True)  # liberado em assumed-breach


@given(ip=st.ip_addresses())
@settings(max_examples=200, deadline=None)
def test_ip_category_is_total(ip) -> None:
    # ip_category nunca levanta para um IP válido e sempre devolve uma classe conhecida.
    assert ip_category(str(ip)) in {
        "metadata",
        "loopback",
        "link-local",
        "private",
        "reserved",
        "public",
    }
