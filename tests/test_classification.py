"""Classificação da informação por engajamento (§10.4).

Falha antes / passa depois: ordem de sensibilidade; a do engajamento é a mais restritiva;
CONFIDENCIAL+ exige redaction; RESTRITO não vai a provedor externo (soberania); banner e
from_str.
"""

from __future__ import annotations

from eigan.policy.classification import (
    Classification,
    banner,
    most_restrictive,
    permits_external_provider,
    requires_redaction,
)


def test_ordering() -> None:
    assert Classification.PUBLIC.rank < Classification.INTERNAL.rank
    assert Classification.CONFIDENTIAL.rank < Classification.RESTRICTED.rank
    assert Classification.RESTRICTED.at_least(Classification.CONFIDENTIAL) is True
    assert Classification.PUBLIC.at_least(Classification.INTERNAL) is False


def test_engagement_is_most_restrictive() -> None:
    levels = [Classification.PUBLIC, Classification.CONFIDENTIAL, Classification.INTERNAL]
    assert most_restrictive(levels) is Classification.CONFIDENTIAL
    assert most_restrictive([]) is Classification.INTERNAL  # default


def test_redaction_required_from_confidential() -> None:
    assert requires_redaction(Classification.INTERNAL) is False
    assert requires_redaction(Classification.CONFIDENTIAL) is True
    assert requires_redaction(Classification.RESTRICTED) is True


def test_restricted_blocks_external_provider() -> None:
    assert permits_external_provider(Classification.CONFIDENTIAL) is True
    assert permits_external_provider(Classification.RESTRICTED) is False  # só soberano


def test_banner_and_from_str() -> None:
    assert "CONFIDENCIAL" in banner(Classification.CONFIDENTIAL)
    assert (
        Classification.from_str("restricted", default=Classification.PUBLIC)
        is Classification.RESTRICTED
    )
    assert (
        Classification.from_str("xxx", default=Classification.INTERNAL) is Classification.INTERNAL
    )
    assert Classification.from_str(None, default=Classification.PUBLIC) is Classification.PUBLIC
