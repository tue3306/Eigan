"""Regressão de segurança SSRF (§7.1): cada bug histórico ganha um teste nomeado.

Dois bugs reais de SSRF já corrigidos (CHANGELOG · auditoria de segurança): metadata
de nuvem em IPv4-mapped IPv6, e IPv6 entre colchetes. Este arquivo trava essas classes
para sempre — a área é empiricamente de alta densidade de defeito.
"""

from __future__ import annotations

import pytest

from eigan.perspective import extract_host
from eigan.security.ssrf import SsrfError, is_metadata_literal, screen_ip


def test_regression_ipv4_mapped_ipv6_metadata_blocked_in_assumed_breach() -> None:
    # BUG: ``::ffff:169.254.169.254`` era visto como link-local → em assumed-breach
    # (allow_private=True) furava o bloqueio "sempre" de metadata (roubo de credencial).
    for form in ("::ffff:169.254.169.254", "::ffff:a9fe:a9fe"):
        assert is_metadata_literal(form), form
    with pytest.raises(SsrfError):
        screen_ip("::ffff:169.254.169.254", allow_private=True)


def test_regression_ipv6_in_brackets_host_extracted() -> None:
    # BUG: ``[::1]:80`` / ``[fd00:ec2::254]:80`` não tinham o host extraído (caíam em
    # HOSTNAME) → loopback liberado em EXTERNAL e o metadata IPv6 passava pelo gate.
    assert extract_host("[::1]:80") == "::1"
    assert extract_host("[fd00:ec2::254]:80") == "fd00:ec2::254"
    assert is_metadata_literal("[fd00:ec2::254]")


def test_all_known_metadata_forms_are_blocked() -> None:
    for form in (
        "169.254.169.254",
        "100.100.100.100",
        "fd00:ec2::254",
        "[fd00:ec2::254]",
        "metadata.google.internal",
        "metadata",
    ):
        assert is_metadata_literal(form), form
