"""Modelo do Knowledge Graph: nós e relacionamentos tipados (Parte 2 do roadmap).

Tudo que o EIGAN descobre vira **nó**; toda relação vira **aresta tipada**. Nada fica
isolado. O modelo é dado puro (sem I/O), original e determinístico — a base sobre a qual
o Correlation Engine constrói cadeias de ataque e a IA responde consultas navegando pelo
grafo, em vez de olhar findings isolados.

Princípios: os tipos vêm do domínio de segurança (conceitos padrão da indústria, P7); a
identidade de um nó é seu ``node_id`` estável; a identidade de uma aresta é a tripla
``(src, kind, dst)``. Nenhuma relação é inventada — quem cria arestas (o Correlation
Engine) só o faz a partir de evidência coletada.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    """Tipos de nó. Subconjunto curado do domínio (ativos, identidade, segurança)."""

    # Organização / rede
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    # Aplicação / dados
    APPLICATION = "application"
    API = "api"
    ENDPOINT = "endpoint"
    DATABASE = "database"
    BUCKET = "bucket"
    # Tecnologia / supply chain
    TECHNOLOGY = "technology"
    CMS = "cms"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    IMAGE = "image"
    CONTAINER = "container"
    POD = "pod"
    NAMESPACE = "namespace"
    REPOSITORY = "repository"
    COMMIT = "commit"
    PIPELINE = "pipeline"
    # Identidade / segredos
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"  # objeto de computador do AD
    CREDENTIAL = "credential"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    SECRET = "secret"
    FILE = "file"
    PROCESS = "process"
    # Segurança / conhecimento
    VULNERABILITY = "vulnerability"
    FINDING = "finding"
    EXPLOIT = "exploit"
    CVE = "cve"
    CWE = "cwe"
    OWASP = "owasp"
    MITRE_TECHNIQUE = "mitre_technique"
    MITRE_TACTIC = "mitre_tactic"
    CONTROL = "control"  # NIST/CIS/ISO/PCI/LGPD — mapeamento indicativo


class EdgeKind(str, Enum):
    """Tipos de relacionamento entre nós."""

    HOSTED_ON = "hosted_on"
    CONTAINS = "contains"
    BELONGS_TO = "belongs_to"
    DEPENDS_ON = "depends_on"
    RUNS = "runs"
    COMMUNICATES_WITH = "communicates_with"
    USES = "uses"
    EXPOSES = "exposes"
    LEAKS = "leaks"
    OWNS = "owns"
    CONNECTED_TO = "connected_to"
    AUTHENTICATED_BY = "authenticated_by"
    REFERENCES = "references"
    AFFECTED_BY = "affected_by"
    EXPLOITS = "exploits"
    MITIGATED_BY = "mitigated_by"
    CORRELATES_WITH = "correlates_with"
    DERIVED_FROM = "derived_from"
    VALIDATED_BY = "validated_by"
    DISCOVERED_BY = "discovered_by"
    HISTORICALLY_RELATED_TO = "historically_related_to"
    # Identidade / Active Directory (arestas de escalonamento de privilégio)
    MEMBER_OF = "member_of"  # principal → grupo
    HAS_CONTROL = "has_control"  # principal controla objeto (attr 'right': GenericAll, …)
    ADMIN_TO = "admin_to"  # principal é admin local em um computador


@dataclass
class Node:
    """Um nó do grafo. ``node_id`` é a identidade estável (idempotência de inserção)."""

    node_id: str
    kind: NodeKind
    label: str = ""
    attributes: dict[str, str] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "label": self.label,
            "attributes": dict(sorted(self.attributes.items())),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Node:
        fs = data.get("first_seen")
        ls = data.get("last_seen")
        return cls(
            node_id=str(data["node_id"]),
            kind=NodeKind(str(data["kind"])),
            label=str(data.get("label", "")),
            attributes={str(k): str(v) for k, v in dict(data.get("attributes") or {}).items()},
            first_seen=datetime.fromisoformat(str(fs)) if fs else None,
            last_seen=datetime.fromisoformat(str(ls)) if ls else None,
        )


@dataclass
class Edge:
    """Uma aresta tipada. Identidade = ``(src, kind, dst)``. ``evidence`` lista as fontes
    (ferramenta/finding) que sustentam a relação — nenhuma relação sem evidência."""

    src: str
    dst: str
    kind: EdgeKind
    attributes: dict[str, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src, self.kind.value, self.dst)

    def to_dict(self) -> dict[str, object]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind.value,
            "attributes": dict(sorted(self.attributes.items())),
            "evidence": sorted(self.evidence),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Edge:
        fs = data.get("first_seen")
        ls = data.get("last_seen")
        return cls(
            src=str(data["src"]),
            dst=str(data["dst"]),
            kind=EdgeKind(str(data["kind"])),
            attributes={str(k): str(v) for k, v in dict(data.get("attributes") or {}).items()},
            evidence=[str(e) for e in list(data.get("evidence") or [])],
            first_seen=datetime.fromisoformat(str(fs)) if fs else None,
            last_seen=datetime.fromisoformat(str(ls)) if ls else None,
        )
