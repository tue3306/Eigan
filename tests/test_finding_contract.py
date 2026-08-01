"""Contrato versionado do Finding — JSON Schema publicável (§24.2).

Falha antes / passa depois: o schema é gerado do modelo (não escrito à mão), carrega a
versão do contrato, contém todos os campos garantidos aos consumidores, e um Finding real
casa a estrutura declarada. Remover um campo garantido quebra o teste (mudança explícita).
"""

from __future__ import annotations

from eigan.findings.contract import (
    FINDING_SCHEMA_VERSION,
    GUARANTEED_FIELDS,
    finding_json_schema,
)
from eigan.findings.schema import Finding, Severity


def test_schema_is_generated_and_versioned() -> None:
    schema = finding_json_schema()
    assert schema["x-contract-version"] == FINDING_SCHEMA_VERSION
    assert FINDING_SCHEMA_VERSION in schema["$id"]
    assert schema["type"] == "object"
    assert "properties" in schema


def test_all_guaranteed_fields_present_in_schema() -> None:
    props = finding_json_schema()["properties"]
    missing = GUARANTEED_FIELDS - set(props)
    assert not missing, f"campos garantidos ausentes do schema: {missing}"


def test_guaranteed_fields_exist_on_the_model() -> None:
    # o contrato não pode garantir um campo que o modelo não tem
    model_fields = set(Finding.model_fields)
    assert GUARANTEED_FIELDS <= model_fields


def test_real_finding_matches_declared_field_names() -> None:
    f = Finding(title="t", severity=Severity.LOW, affected_asset="a", source_tool="x")
    dumped = f.model_dump()
    for field in GUARANTEED_FIELDS:
        assert field in dumped


def test_severity_is_constrained_enum_in_schema() -> None:
    # o consumidor sabe exatamente os valores possíveis de severity
    schema = finding_json_schema()
    defs = schema.get("$defs", {})
    assert "Severity" in defs
    assert set(defs["Severity"]["enum"]) == {"info", "low", "medium", "high", "critical"}
