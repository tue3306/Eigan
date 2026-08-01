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
from .ntlm import NtlmFinding, NtlmHostConfig, assess_ntlm
from .password import PasswordFinding, PasswordPolicy, PwAccount, assess_passwords
from .scenarios import AdSignal, AttackScenario, CombinationRule, correlate_scenarios
from .shadowcreds import AdObjectKeyCred, ShadowCredFinding, assess_shadow_credentials

__all__ = [
    "AdAccount",
    "AdObjectKeyCred",
    "AdSignal",
    "AttackPath",
    "AttackScenario",
    "CaConfiguration",
    "CertificateTemplate",
    "CombinationRule",
    "EscFinding",
    "KerberosFinding",
    "NtlmFinding",
    "NtlmHostConfig",
    "PasswordFinding",
    "PasswordPolicy",
    "PathStep",
    "PwAccount",
    "ShadowCredFinding",
    "assess_kerberos",
    "assess_ntlm",
    "assess_passwords",
    "assess_shadow_credentials",
    "classify_adcs",
    "correlate_scenarios",
    "find_attack_paths",
    "shortest_attack_path",
]
