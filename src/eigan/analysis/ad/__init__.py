"""Análise de segurança de Active Directory (TIER X) — implementação original.

Reusa o Knowledge Graph (`eigan.graph`) como substrato: objetos de AD (usuários, grupos,
computadores) e relações de controle (membership, controle sobre objeto, admin local)
viram nós e arestas tipadas. O analisador de **attack paths** encontra caminhos de
escalonamento de privilégio até um alvo de alto valor (ex.: Domain Admins), com algoritmo
próprio (busca em grafo), sem copiar de nenhuma ferramenta de terceiro (P7).
"""

from .adcs import CaConfiguration, CertificateTemplate, EscFinding, classify_adcs
from .attackpath import AttackPath, PathStep, find_attack_paths, shortest_attack_path
from .kerberos import AdAccount, KerberosFinding, assess_kerberos

__all__ = [
    "AdAccount",
    "AttackPath",
    "CaConfiguration",
    "CertificateTemplate",
    "EscFinding",
    "KerberosFinding",
    "PathStep",
    "assess_kerberos",
    "classify_adcs",
    "find_attack_paths",
    "shortest_attack_path",
]
