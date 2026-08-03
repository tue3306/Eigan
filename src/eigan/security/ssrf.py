"""Blindagem de SSRF — cliente HTTP que não vira pivô de ataque (ADR-0015).

O gate de escopo valida o alvo ORIGINAL, mas um alvo malicioso pode **redirecionar**
para ``169.254.169.254`` (metadata de nuvem → roubo de credencial) ou para hosts
internos, furando o escopo. Este módulo fecha isso de forma sistêmica:

- **Metadata de nuvem é bloqueado SEMPRE** (independe da perspectiva).
- Loopback/link-local/RFC1918/ULA/reservado são bloqueados quando ``allow_private``
  é falso (scan externo); liberados em assumed-breach (interno/unificado).
- **Redirects não são seguidos automaticamente**: cada destino é revalidado.
- **Anti-DNS-rebinding**: o host é resolvido, cada IP é triado, e a conexão é
  fixada (*pinned*) no IP validado — o Host header preserva o nome original.

Sem dependência de terceiros (``http.client`` + ``socket`` + ``ipaddress``). Nunca
``shell=True`` (nem subprocess). Ver ``plugins/red/exposure`` (primeiro consumidor).
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlsplit

# Endpoints de metadata de nuvem conhecidos (AWS/GCP/Azure/Oracle · Alibaba · IPv6).
# NUNCA são alvo legítimo de scanner ativo — só pivô de SSRF. Bloqueados sempre.
METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS/GCP/Azure/DigitalOcean/OpenStack
        "100.100.100.100",  # Alibaba Cloud
        "fd00:ec2::254",  # AWS IPv6
    }
)
METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata"})

_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class SsrfError(Exception):
    """Destino recusado por política anti-SSRF (metadata/interno fora do permitido)."""


def _normalize_mapped(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """IPv4-mapped IPv6 (``::ffff:a.b.c.d``) roteia, na pilha dupla, para o IPv4
    embutido — logo tem de ser classificado pelo IPv4 real. Sem isto, um endpoint
    de metadata na forma ``::ffff:169.254.169.254`` seria visto como link-local e,
    em assumed-breach (``allow_private=True``), furaria o bloqueio 'sempre' de
    metadata (SSRF → roubo de credencial de nuvem)."""
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def is_metadata_literal(host: str) -> bool:
    """O host é, literalmente (sem DNS), um endpoint de metadata? (usado pelo gate)."""
    h = (host or "").strip().lower().strip("[]")
    if h in METADATA_HOSTS:
        return True
    try:
        ip = _normalize_mapped(ipaddress.ip_address(h))
    except ValueError:
        return False
    return str(ip) in METADATA_IPS


def ip_category(ip_str: str) -> str:
    """Classe do IP: metadata | loopback | link-local | private | reserved | public."""
    ip = _normalize_mapped(ipaddress.ip_address(ip_str))
    if str(ip) in METADATA_IPS:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:  # RFC1918 + IPv6 ULA (fc00::/7)
        return "private"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved"
    return "public"


def screen_ip(ip_str: str, *, allow_private: bool) -> None:
    """Levanta :class:`SsrfError` se o IP é proibido. Metadata é sempre proibido."""
    cat = ip_category(ip_str)
    if cat == "metadata":
        raise SsrfError(f"metadata de nuvem bloqueado (SSRF): {ip_str}")
    if cat == "public":
        return
    if allow_private:  # assumed-breach (interno/unificado) pode tocar a rede interna
        return
    raise SsrfError(f"endereço {cat} bloqueado no modo externo (SSRF): {ip_str}")


def resolve_and_screen(host: str, *, allow_private: bool) -> list[str]:
    """Resolve ``host`` e tria TODOS os IPs (bloqueia se qualquer um é proibido).

    Retorna a lista de IPs validados (para *pinning*). Levanta ``SsrfError`` se
    algum IP resolvido é proibido — defesa contra hosts que resolvem para metadata/
    interno (inclui o caso de múltiplos registros A/AAAA)."""
    host = (host or "").strip().strip("[]")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SsrfError(f"host não resolvido: {host}") from exc
    ips: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise SsrfError(f"host sem endereço: {host}")
    for ip in ips:
        screen_ip(ip, allow_private=allow_private)
    return ips


def _make_conn(scheme: str, ip: str, port: int | None, timeout: float):
    """Conexão fixada no IP validado (anti-rebinding). HTTPS com verify off (o ALVO
    sob teste não é fonte confiável — contexto de pentest)."""
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(ip, port or 443, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(ip, port or 80, timeout=timeout)


def _host_header(host: str, port: int | None, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    if port and port != default:
        return f"{host}:{port}"
    return host


def safe_get(
    url: str,
    *,
    allow_private: bool,
    timeout: float = 8.0,
    max_bytes: int = 64 * 1024,
    user_agent: str = "EIGAN/0.0.0 (authorized security assessment)",
    max_redirects: int = 3,
) -> tuple[int, str, str] | None:
    """GET blindado contra SSRF: (status, corpo, url_final) ou ``None`` se inacessível.

    Resolve + tria + fixa o IP a cada salto; segue redirect manualmente até
    ``max_redirects``, revalidando cada destino. Levanta ``SsrfError`` se qualquer
    salto aponta para metadata/interno proibido — o chamador decide o que fazer."""
    current = url
    redirects = 0
    while True:
        parts = urlsplit(current)
        scheme = parts.scheme or "http"
        if scheme not in ("http", "https"):
            return None
        host = parts.hostname
        if not host:
            return None
        # ``SplitResult.port`` levanta ValueError p/ porta fora de 0-65535 ou
        # não-numérica. O destino é atacante-controlado (revalidamos o Location
        # do redirect), então lê a porta aqui — fora do try de request — e trata
        # porta inválida como inacessível (None), sem estourar o contrato.
        try:
            port = parts.port
        except ValueError:
            return None
        ips = resolve_and_screen(host, allow_private=allow_private)  # pode levantar SsrfError
        conn = _make_conn(scheme, ips[0], port, timeout)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        headers = {
            "User-Agent": user_agent,
            "Host": _host_header(host, port, scheme),
            "Accept": "*/*",
            "Connection": "close",
        }
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            if status in _REDIRECT_CODES and redirects < max_redirects:
                location = resp.headers.get("Location")
                resp.read()
                conn.close()
                if not location:
                    return status, "", current
                current = urljoin(current, location)  # revalidado no topo do loop
                redirects += 1
                continue
            body = resp.read(max_bytes).decode("utf-8", errors="replace")
            conn.close()
            return status, body, current
        except (OSError, http.client.HTTPException, ValueError):
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            return None
