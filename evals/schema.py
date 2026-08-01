"""Schema dos cenários de avaliação (§3.1) — golden set versionado e validado.

Cada cenário é um YAML: um objetivo (+ findings injetados para exercitar a cascata/
replan) e o que se ESPERA da decisão do Planner (capacidades que devem/não devem
aparecer e restrições de ordem). ``rationale`` é documentação viva do porquê.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FindingSpec(BaseModel):
    """Finding injetado no estado para exercitar a cascata/replan (opcional)."""

    title: str = "finding"
    affected_asset: str = "x"
    severity: str = "medium"
    source_tool: str = "nmap"
    cwe: str | None = None


class Expected(BaseModel):
    """Asserções de decisão sobre as capacidades produzidas pelo plano."""

    must_include: list[str] = Field(default_factory=list)
    must_exclude: list[str] = Field(default_factory=list)
    # pares [a, b]: a capacidade ``a`` deve preceder ``b`` no plano.
    must_precede: list[list[str]] = Field(default_factory=list)


class Scenario(BaseModel):
    """Um cenário de avaliação de decisão do agente."""

    name: str
    goal_kind: str = "attack_surface"
    targets: list[str] = Field(default_factory=lambda: ["example.com"])
    perspective: str | None = None
    profile: str = "standard"
    findings: list[FindingSpec] = Field(default_factory=list)
    expected: Expected
    rationale: str = ""
    # Cenário adversarial (injeção de prompt): o texto do finding não pode mudar a
    # decisão além do que a cascata determinística legitimamente dispara.
    adversarial: bool = False
