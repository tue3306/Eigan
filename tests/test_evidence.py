"""Cadeia de custódia da evidência (§21.1).

Falha antes / passa depois: selar produz hash+data determinísticos; verify aceita o
conteúdo íntegro e rejeita qualquer alteração (byte, truncamento); str e bytes; o selo
é serializável para a trilha.
"""

from __future__ import annotations

from datetime import datetime, timezone

from eigan.findings.evidence import EvidenceRecord, seal_evidence, verify_evidence

_AT = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


def test_seal_is_deterministic_and_records_metadata() -> None:
    rec = seal_evidence("saida do nmap", source="nmap", at=_AT)
    again = seal_evidence("saida do nmap", source="nmap", at=_AT)
    assert rec == again  # mesmo conteúdo + mesma data ⇒ mesmo selo
    assert rec.source == "nmap"
    assert rec.collected_at == _AT.isoformat()
    assert rec.size == len("saida do nmap".encode())


def test_verify_accepts_intact_and_rejects_tampering() -> None:
    content = "GET /admin HTTP/1.1\nHost: alvo"
    rec = seal_evidence(content, source="httpx", at=_AT)
    assert verify_evidence(rec, content) is True
    assert verify_evidence(rec, content + " ") is False  # 1 byte a mais
    assert verify_evidence(rec, content.replace("admin", "root")) is False


def test_bytes_and_str_equivalent() -> None:
    rec_str = seal_evidence("abc", source="t", at=_AT)
    rec_bytes = seal_evidence(b"abc", source="t", at=_AT)
    assert rec_str.sha256 == rec_bytes.sha256
    assert verify_evidence(rec_str, b"abc") is True


def test_different_content_different_seal() -> None:
    a = seal_evidence("a", source="t", at=_AT)
    b = seal_evidence("b", source="t", at=_AT)
    assert a.sha256 != b.sha256


def test_record_is_serializable_for_trail() -> None:
    rec = seal_evidence("x", source="nmap", at=_AT)
    d = rec.to_dict()
    assert set(d) == {"sha256", "collected_at", "source", "size"}
    assert d["sha256"] == rec.sha256
    # reconstrução manual a partir do dict preserva a verificação
    restored = EvidenceRecord(**d)  # type: ignore[arg-type]
    assert verify_evidence(restored, "x") is True
