from __future__ import annotations

import ipaddress
import hashlib
import os
import re
import socket
import subprocess
from dataclasses import dataclass
from urllib.parse import urlsplit

from ai4sec_platform.core.url_security import PublicUrlPolicy, resolved_addresses


DEFAULT_REPRO_EGRESS_DOMAINS = (
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "githubusercontent.com",
    "pypi.org",
    "pythonhosted.org",
    "pypi.tuna.tsinghua.edu.cn",
    "registry.npmjs.org",
    "registry.npmmirror.com",
    "repo.maven.apache.org",
    "maven.org",
    "crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "storage.googleapis.com",
    "huggingface.co",
)


def validate_repro_egress_runtime(run_command=None) -> None:
    run_command = run_command or subprocess.run
    checks = [
        ["docker", "network", "inspect", "bridge"],
        ["iptables", "-S", "DOCKER-USER"],
    ]
    for command in checks:
        result = run_command(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"reproduction egress enforcement is unavailable: {' '.join(command)}")


@dataclass(frozen=True)
class ReproEgressPolicy:
    domains: tuple[str, ...]
    public_addresses: tuple[str, ...]
    host_addresses: tuple[tuple[str, str], ...]
    gateway_addresses: tuple[str, ...]
    gateway_host: str
    gateway_port: int


def build_repro_egress_policy(repo_url: str, gateway_url: str, *, resolver=None) -> ReproEgressPolicy:
    repo_host = _validated_public_host(repo_url, resolver=resolver)
    gateway = urlsplit(gateway_url)
    if gateway.scheme not in {"http", "https"} or not gateway.hostname:
        raise RuntimeError("invalid AI4SEC Model Gateway URL")
    extra_domains = tuple(filter(None, (value.strip().casefold() for value in os.getenv("REPRO_EGRESS_EXTRA_DOMAINS", "").split(","))))
    domains = tuple(dict.fromkeys([repo_host, *DEFAULT_REPRO_EGRESS_DOMAINS, *extra_domains]))
    addresses: set[str] = set()
    host_addresses: list[tuple[str, str]] = []
    for domain in domains:
        try:
            resolved = resolved_addresses(domain, 443, resolver=resolver)
        except socket.gaierror as exc:
            if domain == repo_host:
                raise RuntimeError(f"cannot resolve reproduction repository host: {domain}") from exc
            continue
        if any(not address.is_global for address in resolved):
            raise RuntimeError(f"reproduction egress domain resolves to a non-public address: {domain}")
        addresses.update(str(address) for address in resolved)
        host_addresses.extend((domain, str(address)) for address in resolved)
    gateway_host = gateway.hostname.casefold().rstrip(".")
    gateway_addresses: tuple[str, ...] = ()
    if gateway_host != "host.docker.internal":
        gateway_error = PublicUrlPolicy().validate(gateway_url, resolve_dns=True, resolver=resolver)
        if gateway_error:
            raise RuntimeError(f"unsafe Model Gateway URL: {gateway_error}")
        resolved_gateway = resolved_addresses(gateway_host, gateway.port or 443, resolver=resolver)
        gateway_addresses = tuple(sorted(str(address) for address in resolved_gateway))
        addresses.update(gateway_addresses)
        host_addresses.extend((gateway_host, address) for address in gateway_addresses)
    return ReproEgressPolicy(
        domains=domains,
        public_addresses=tuple(sorted(addresses)),
        host_addresses=tuple(sorted(set(host_addresses))),
        gateway_addresses=gateway_addresses,
        gateway_host=gateway_host,
        gateway_port=gateway.port or (443 if gateway.scheme == "https" else 80),
    )


class DockerEgressGuard:
    def __init__(self, *, task_id: int, container_name: str, policy: ReproEgressPolicy, run_command=None) -> None:
        self.task_id = task_id
        self.container_name = container_name
        self.policy = policy
        self.run_command = run_command or subprocess.run
        suffix = hashlib.sha256(container_name.encode()).hexdigest()[:6]
        self.chain = f"A4R_{task_id}_{suffix}"
        self.container_ip = ""
        self.gateway_ip = ""
        self.active = False

    def install(self) -> dict:
        self.container_ip = self._output(["docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.container_name])
        if not _is_ip(self.container_ip):
            raise RuntimeError("cannot determine reproduction container IP")
        if self.policy.gateway_host == "host.docker.internal":
            self.gateway_ip = self._output(["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"])
            if not _is_ip(self.gateway_ip):
                raise RuntimeError("cannot determine Docker bridge gateway IP")
        commands = [
            ["iptables", "-N", self.chain],
            ["iptables", "-A", self.chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ]
        for address in self.policy.public_addresses:
            if ":" in address:
                continue
            commands.append(["iptables", "-A", self.chain, "-d", address, "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "ACCEPT"])
        if self.gateway_ip:
            commands.append(["iptables", "-A", self.chain, "-d", self.gateway_ip, "-p", "tcp", "--dport", str(self.policy.gateway_port), "-j", "ACCEPT"])
        for address in self.policy.gateway_addresses:
            if ":" not in address:
                commands.append(["iptables", "-A", self.chain, "-d", address, "-p", "tcp", "--dport", str(self.policy.gateway_port), "-j", "ACCEPT"])
        commands.extend([
            ["iptables", "-A", self.chain, "-j", "REJECT"],
            ["iptables", "-I", "DOCKER-USER", "1", "-s", self.container_ip, "-j", self.chain],
        ])
        try:
            for command in commands:
                self._run(command)
            self.active = True
        except Exception:
            self.remove()
            raise
        return self.summary()

    def remove(self) -> dict:
        counters = self.counters()
        if self.container_ip:
            self._run(["iptables", "-D", "DOCKER-USER", "-s", self.container_ip, "-j", self.chain], check=False)
        self._run(["iptables", "-F", self.chain], check=False)
        self._run(["iptables", "-X", self.chain], check=False)
        self.active = False
        denied_packets, denied_bytes = _reject_counters(counters)
        return {**self.summary(), "counters": counters, "denied_packets": denied_packets, "denied_bytes": denied_bytes}

    def counters(self) -> str:
        if not self.active:
            return ""
        result = self.run_command(["iptables", "-L", self.chain, "-n", "-v", "-x"], capture_output=True, text=True)
        return str(result.stdout or "")[:5000]

    def summary(self) -> dict:
        return {
            "chain": self.chain,
            "container_ip": self.container_ip,
            "gateway_ip": self.gateway_ip,
            "gateway_port": self.policy.gateway_port,
            "domains": list(self.policy.domains),
            "allowed_public_ips": len(self.policy.public_addresses),
            "host_mappings": len(self.policy.host_addresses),
        }

    def _output(self, command: list[str]) -> str:
        result = self._run(command)
        return str(result.stdout or "").strip()

    def _run(self, command: list[str], *, check: bool = True):
        result = self.run_command(command, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"egress enforcement command failed: {' '.join(command)}: {str(result.stderr or '').strip()}")
        return result


def _validated_public_host(url: str, *, resolver=None) -> str:
    error = PublicUrlPolicy(domain_allowlist=("github.com",)).validate(url, resolve_dns=True, resolver=resolver)
    if error:
        raise RuntimeError(f"unsafe reproduction repository URL: {error}")
    return str(urlsplit(url).hostname or "").casefold().rstrip(".")


def _is_ip(value: str) -> bool:
    try:
        return bool(ipaddress.ip_address(value))
    except ValueError:
        return False


def _reject_counters(output: str) -> tuple[int, int]:
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == "REJECT" and fields[0].isdigit() and fields[1].isdigit():
            return int(fields[0]), int(fields[1])
    return 0, 0
