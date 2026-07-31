"""Objetivo (Goal) e orçamento de parada — domínio puro do núcleo cognitivo.

Um :class:`Goal` é *o que o usuário quer*, não *como* fazer. O Planner traduz o
objetivo em capacidades (ADR-0007); as ferramentas são detalhe de implementação
escolhido depois pelo Tool Selection Engine. Módulo só-stdlib: é domínio e não
conhece infraestrutura.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ...capability import Capability
from ...perspective import Perspective

C = Capability


class GoalKind(str, Enum):
    """Objetivos de alto nível que o usuário pode pedir.

    Cada objetivo mapeia para uma *estratégia* (sequência de capacidades) em
    :data:`GOAL_CAPABILITIES`. Objetivos cujas capacidades ainda não têm plugin
    real produzem um plano honesto: as etapas aparecem como *sugeridas, não
    executadas* (scaffold), nunca fingindo rodar.
    """

    FULL_ASSESSMENT = "full_assessment"  # modo produto: recon externo + rede num só scan
    ATTACK_SURFACE = "attack_surface"  # superfície de ataque externa (recon amplo)
    EXTERNAL_EXPOSURE = "external_exposure"  # validar exposição externa (portas/serviços/web)
    WEB_VULNERABILITIES = "web_vulnerabilities"  # cadeia web até templates de vuln
    NETWORK_ASSESSMENT = "network_assessment"  # descoberta de host/porta/serviço (inside-out)
    # ── roadmap (scaffold honesto — sem agente real ainda) ────────────────────
    AD_ENUMERATION = "ad_enumeration"
    CLOUD_ASSESSMENT = "cloud_assessment"

    @classmethod
    def from_str(cls, value: str) -> "GoalKind":
        # aceita hífen ou underscore ("attack-surface" == "attack_surface").
        norm = value.strip().lower().replace("-", "_")
        try:
            return cls(norm)
        except ValueError as exc:
            raise ValueError(
                f"Objetivo desconhecido: {value!r}. Válidos: {[g.value for g in cls]}"
            ) from exc

    @property
    def label(self) -> str:
        return {
            GoalKind.FULL_ASSESSMENT: "Avaliação completa (recon + rede + web)",
            GoalKind.ATTACK_SURFACE: "Avaliar superfície de ataque",
            GoalKind.EXTERNAL_EXPOSURE: "Validar exposição externa",
            GoalKind.WEB_VULNERABILITIES: "Descobrir vulnerabilidades web",
            GoalKind.NETWORK_ASSESSMENT: "Avaliar a rede (inside-out)",
            GoalKind.AD_ENUMERATION: "Enumerar Active Directory",
            GoalKind.CLOUD_ASSESSMENT: "Avaliar exposição em nuvem",
        }[self]


# Estratégia declarativa: objetivo → capacidades em ordem de intenção. O Planner
# intersecta isto com as capacidades que o registry realmente provê e com a
# ordem canônica do pipeline. Editar aqui = nova estratégia, sem tocar o loop.
GOAL_CAPABILITIES: dict[GoalKind, tuple[Capability, ...]] = {
    # Modo produto (UNIFIED): união do recon externo com a descoberta de rede, na
    # ordem canônica do pipeline. Descobre superfície pública E hosts/portas
    # internos no mesmo scan; a cascata aprofunda a partir do que for encontrado.
    GoalKind.FULL_ASSESSMENT: (
        C.SUBDOMAIN_ENUMERATION,
        C.DNS_RESOLUTION,
        C.DNS_ENUMERATION,
        C.HOST_DISCOVERY,
        C.PORT_DISCOVERY,
        C.SERVICE_DETECTION,
        C.WEB_PROBE,
        C.CMS_SCAN,
        C.WEB_CRAWL,
        C.PARAM_DISCOVERY,
        C.SECRETS_EXPOSURE,
        # lentas por último (nuclei, nikto, testssl):
        C.VULN_TEMPLATE_SCAN,
        C.WEB_SERVER_SCAN,
        C.TLS_ASSESSMENT,
    ),
    GoalKind.ATTACK_SURFACE: (
        C.SUBDOMAIN_ENUMERATION,
        C.DNS_RESOLUTION,
        C.DNS_ENUMERATION,
        C.PORT_DISCOVERY,
        C.SERVICE_DETECTION,
        C.WEB_PROBE,
        C.SECRETS_EXPOSURE,
        C.TLS_ASSESSMENT,
        C.VULN_TEMPLATE_SCAN,
    ),
    GoalKind.EXTERNAL_EXPOSURE: (
        C.DNS_RESOLUTION,
        C.PORT_DISCOVERY,
        C.SERVICE_DETECTION,
        C.WEB_PROBE,
        C.TLS_ASSESSMENT,
    ),
    GoalKind.WEB_VULNERABILITIES: (
        C.WEB_PROBE,
        C.WEB_CRAWL,
        C.PARAM_DISCOVERY,
        C.CMS_SCAN,
        C.SECRETS_EXPOSURE,
        C.VULN_TEMPLATE_SCAN,
    ),
    GoalKind.NETWORK_ASSESSMENT: (
        C.HOST_DISCOVERY,
        C.PORT_DISCOVERY,
        C.SERVICE_DETECTION,
        C.WEB_PROBE,
        C.TLS_ASSESSMENT,
    ),
    GoalKind.AD_ENUMERATION: (C.AD_ENUMERATION,),
    GoalKind.CLOUD_ASSESSMENT: (C.CLOUD_AUDIT, C.CLOUD_STORAGE_ENUM),
}

# Perspectiva default de cada objetivo (o usuário pode sobrepor).
GOAL_PERSPECTIVE: dict[GoalKind, Perspective] = {
    GoalKind.FULL_ASSESSMENT: Perspective.UNIFIED,
    GoalKind.ATTACK_SURFACE: Perspective.EXTERNAL,
    GoalKind.EXTERNAL_EXPOSURE: Perspective.EXTERNAL,
    GoalKind.WEB_VULNERABILITIES: Perspective.EXTERNAL,
    GoalKind.NETWORK_ASSESSMENT: Perspective.INTERNAL,
    GoalKind.AD_ENUMERATION: Perspective.INTERNAL,
    GoalKind.CLOUD_ASSESSMENT: Perspective.EXTERNAL,
}


@dataclass(frozen=True)
class Budget:
    """Limites de parada — o usuário controla o quão longe o loop vai."""

    max_capabilities: int = 24  # teto duro de etapas executadas (anti-loop)
    max_wall_seconds: float | None = None  # tempo de parede; None = sem limite
    stop_on_no_new_evidence: bool = True  # encerra quando o replan não agrega nada
    # Teto duro de alvos (ADR-0018): a expansão dirigida por descoberta (subdomínio/
    # IP/host viram novos alvos) NÃO pode explodir. Inclui os alvos originais.
    max_targets: int = 64
    # Teto de IA (§2.1): interrompe o loop cognitivo graciosamente ao atingir o
    # consumo acumulado — o piso de segurança contra um loop adaptativo custoso. O
    # teto de TOKEN é sempre confiável (medido do provedor). O de CUSTO só é aplicado
    # quando o preço é verificado (`config/ai_pricing.yaml`); sem preço verificado o
    # custo é UNVERIFIED e o teto de token governa (P1 — nunca estima). A IA é
    # obrigatória (ADR-0012): há sempre ao menos o plano inicial, e o teto interrompe
    # as chamadas SEGUINTES ao ser alcançado. None = sem limite. Padrão conservador:
    # o operador declara o teto por scan (CLI/API).
    max_ai_tokens: int | None = None
    max_ai_cost_usd: float | None = None

    def __post_init__(self) -> None:
        if self.max_capabilities < 1:
            raise ValueError("max_capabilities deve ser >= 1")
        if self.max_wall_seconds is not None and self.max_wall_seconds <= 0:
            raise ValueError("max_wall_seconds deve ser > 0 ou None")
        if self.max_targets < 1:
            raise ValueError("max_targets deve ser >= 1")
        if self.max_ai_tokens is not None and self.max_ai_tokens < 1:
            raise ValueError("max_ai_tokens deve ser >= 1 ou None")
        if self.max_ai_cost_usd is not None and self.max_ai_cost_usd <= 0:
            raise ValueError("max_ai_cost_usd deve ser > 0 ou None")


@dataclass(frozen=True)
class Goal:
    """O objetivo do usuário. Imutável — o Planner deriva estratégia a partir dele."""

    kind: GoalKind
    targets: tuple[str, ...]
    perspective: Perspective
    profile: str = "standard"
    budget: Budget = field(default_factory=Budget)

    def __post_init__(self) -> None:
        if not self.targets:
            raise ValueError("Goal exige ao menos um alvo.")

    @property
    def strategy(self) -> tuple[Capability, ...]:
        """Capacidades da estratégia declarada para este objetivo."""
        return GOAL_CAPABILITIES.get(self.kind, ())

    @classmethod
    def build(
        cls,
        kind: GoalKind,
        targets: list[str],
        *,
        perspective: Perspective | None = None,
        profile: str = "standard",
        budget: Budget | None = None,
    ) -> "Goal":
        """Constrói um Goal resolvendo a perspectiva default do objetivo."""
        persp = perspective or GOAL_PERSPECTIVE.get(kind, Perspective.EXTERNAL)
        return cls(
            kind=kind,
            targets=tuple(targets),
            perspective=persp,
            profile=profile,
            budget=budget or Budget(),
        )
