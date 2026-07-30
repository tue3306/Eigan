"""Coerência da fronteira honesta (§0.3): ``Agent.built`` vs. execução real.

Garante por CI o que antes era só convenção documentada: um agente ``built=True``
executa de fato (cada capacidade que declara tem plugin **executável** — runner
carregado, não só metadata) e um agente scaffold (``built=False``) **não** tem
caminho de execução alcançável (nenhum plugin executável). A fronteira honesta é
o principal ativo ético do projeto; aqui ela vira invariante verificado.

Divergiu? Corrija a **flag** em ``engine/cognitive/agent.py`` (ou o roteamento/
plugin) — **nunca** o teste.
"""

from __future__ import annotations

import pytest

from eigan.engine.cognitive.agent import AgentRegistry
from eigan.engine.registry import PluginRegistry


@pytest.fixture(scope="module")
def registry() -> PluginRegistry:
    return PluginRegistry.discover()


def _executable_caps(registry: PluginRegistry) -> set:
    """Capacidades com ≥1 plugin **executável** (runner carregado).

    ``PluginRegistry.capabilities()`` inclui capacidades apenas *declaradas* por
    plugins scaffold (``roadmap: true``, ``runner=None``); aqui filtramos as que
    de fato têm um runner — o que a fronteira honesta afirma sobre ``built=True``.
    """
    return {
        cap
        for cap in registry.capabilities()
        if any(spec.runner is not None for spec in registry.for_capability(cap))
    }


def test_built_agents_execute_every_declared_capability(registry: PluginRegistry) -> None:
    executable = _executable_caps(registry)
    agents = AgentRegistry.default()
    offenders = sorted(
        (agent.name, cap.value)
        for agent in agents.built()
        for cap in agent.capabilities
        if cap not in executable
    )
    assert not offenders, (
        "agente(s) built=True sem plugin executável para uma capacidade declarada "
        f"— a fronteira honesta mente; corrija a flag em agent.py, não o teste: {offenders}"
    )


def test_scaffold_agents_have_no_reachable_execution(registry: PluginRegistry) -> None:
    executable = _executable_caps(registry)
    agents = AgentRegistry.default()
    offenders = sorted(
        (agent.name, cap.value)
        for agent in agents.scaffolds()
        for cap in agent.capabilities
        if cap in executable
    )
    assert not offenders, (
        "agente(s) built=False com plugin executável — a flag deveria ser "
        f"built=True (scaffold que na verdade executa): {offenders}"
    )


def test_executable_capabilities_are_routed_to_a_built_agent(registry: PluginRegistry) -> None:
    """Todo plugin executável é roteado por um agente ``built=True``.

    Uma capacidade executável sem agente dono (ou dona de um scaffold) nunca
    rodaria — o engine a trataria como *sugerida, não executada* —, contradizendo
    a existência do plugin real. Pega plugin novo adicionado sem ligar um agente.
    """
    agents = AgentRegistry.default()
    orphans = sorted(
        cap.value
        for cap in _executable_caps(registry)
        if (owner := agents.for_capability(cap)) is None or not owner.built
    )
    assert not orphans, (
        "capacidade executável sem agente built=True que a roteie "
        f"(plugin real inalcançável pela IA): {orphans}"
    )
