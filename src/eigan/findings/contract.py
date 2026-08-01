"""Contrato versionado do `Finding` — JSON Schema publicável (§24.2).

Sistemas externos (SIEM/CI) consomem o `Finding` e seus exports. Sem um contrato
versionado, cada mudança de schema quebra integração de cliente em silêncio. Este módulo
expõe o **JSON Schema** do `Finding` (gerado do próprio modelo Pydantic — nunca escrito à
mão e desatualizado, P1/P2) carimbado com uma **versão de contrato** explícita, e declara
o conjunto de campos que o contrato garante.

Regra de compatibilidade (liga ao §24.1): remover/renomear um campo garantido ou apertar
um tipo é mudança **quebrante** — exige subir `FINDING_SCHEMA_VERSION` deliberadamente. O
teste de contrato falha se um campo garantido some, tornando a quebra explícita.
"""

from __future__ import annotations

from typing import Any

from .schema import Finding

# Versão do CONTRATO de dados do Finding (independe da versão do produto). Suba
# deliberadamente quando o contrato mudar de forma quebrante.
FINDING_SCHEMA_VERSION = "1.0"

_SCHEMA_ID = "https://github.com/tue3306/eigan/schemas/finding-{version}.json"

# Campos que o contrato garante aos consumidores (SIEM/CI). Um campo garantido só
# desaparece com bump de versão — o teste de contrato trava isso.
GUARANTEED_FIELDS: frozenset[str] = frozenset(
    {
        "title",
        "severity",
        "affected_asset",
        "source_tool",
        "perspective",
        "cwe",
        "owasp",
        "description",
        "evidence",
        "confidence",
        "status",
    }
)


def finding_json_schema() -> dict[str, Any]:
    """JSON Schema do `Finding`, gerado do modelo e carimbado com a versão do contrato."""
    schema = Finding.model_json_schema()
    schema["$id"] = _SCHEMA_ID.format(version=FINDING_SCHEMA_VERSION)
    schema["x-contract-version"] = FINDING_SCHEMA_VERSION
    return schema
