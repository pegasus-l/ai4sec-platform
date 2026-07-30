from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit


Resolver = Callable[..., list[tuple[Any, ...]]]


@dataclass(frozen=True)
class PublicUrlPolicy:
    domain_allowlist: tuple[str, ...] = ()
    domain_blocklist: tuple[str, ...] = ()
    block_private_networks: bool = True

    def validate(self, url: str, *, resolve_dns: bool = False, resolver: Resolver | None = None) -> str:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return "unsupported_or_missing_url"
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return "unsupported_or_missing_url"
        if parsed.username is not None or parsed.password is not None:
            return "url_credentials_blocked"
        hostname = parsed.hostname.casefold().rstrip(".")
        if self.domain_allowlist and not domain_matches(hostname, self.domain_allowlist):
            return "domain_not_allowed"
        if domain_matches(hostname, self.domain_blocklist):
            return "domain_blocked"
        if self.block_private_networks and hostname_is_private(hostname):
            return "private_network_blocked"
        if resolve_dns and self.block_private_networks:
            try:
                addresses = resolved_addresses(hostname, port or (443 if parsed.scheme == "https" else 80), resolver=resolver)
            except socket.gaierror:
                return "dns_resolution_failed"
            if not addresses:
                return "dns_resolution_failed"
            if any(not address.is_global for address in addresses):
                return "private_network_blocked"
        return ""


class ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, policy: PublicUrlPolicy) -> None:
        self.policy = policy

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        error = self.policy.validate(new_url, resolve_dns=True)
        if error:
            raise urllib.error.URLError(error)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def domain_matches(hostname: str, domains: tuple[str, ...]) -> bool:
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in domains)


def hostname_is_private(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return not address.is_global


def resolved_addresses(hostname: str, port: int, *, resolver: Resolver | None = None) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    resolver = resolver or socket.getaddrinfo
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for result in resolver(hostname, port, type=socket.SOCK_STREAM):
        sockaddr = result[4]
        if sockaddr:
            addresses.add(ipaddress.ip_address(sockaddr[0]))
    return addresses
