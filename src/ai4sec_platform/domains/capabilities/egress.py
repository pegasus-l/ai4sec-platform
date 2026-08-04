from __future__ import annotations

import hashlib
import json
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
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "pypi.org",
    "pythonhosted.org",
    "files.pythonhosted.org",
    "pypi.tuna.tsinghua.edu.cn",
    "registry.npmjs.org",
    "registry.npmmirror.com",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "maven.org",
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "storage.googleapis.com",
    "huggingface.co",
)
REPRO_EGRESS_HELPER = os.environ.get(
    "REPRO_EGRESS_HELPER",
    "/usr/local/libexec/ai4sec-repro-egress-helper",
)


def validate_repro_egress_runtime(run_command=None, *, gateway_url: str = "") -> None:
    run_command = run_command or subprocess.run
    gateway = urlsplit(gateway_url) if gateway_url else None
    request = {"action": "preflight"}
    if gateway:
        request["gateway_port"] = gateway.port or (443 if gateway.scheme == "https" else 80)
    result = run_command(
        ["sudo", "-n", REPRO_EGRESS_HELPER],
        input=json.dumps(request),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = _helper_error(result)
        raise RuntimeError(f"reproduction egress helper is unavailable: {detail}")


@dataclass(frozen=True)
class ReproEgressPolicy:
    domains: tuple[str, ...]
    public_addresses: tuple[str, ...]
    host_addresses: tuple[tuple[str, str], ...]
    gateway_addresses: tuple[str, ...]
    gateway_host: str
    gateway_port: int


def build_repro_egress_policy(
    repo_url: str,
    gateway_url: str,
    *,
    approved_domains: tuple[str, ...] = (),
    resolver=None,
) -> ReproEgressPolicy:
    repo_host = _validated_public_host(repo_url, resolver=resolver)
    gateway = urlsplit(gateway_url)
    if gateway.scheme not in {"http", "https"} or not gateway.hostname:
        raise RuntimeError("invalid AI4SEC Model Gateway URL")
    extra_domains = tuple(filter(None, (value.strip().casefold() for value in os.getenv("REPRO_EGRESS_EXTRA_DOMAINS", "").split(","))))
    domains = tuple(dict.fromkeys([repo_host, *DEFAULT_REPRO_EGRESS_DOMAINS, *extra_domains, *approved_domains]))
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
        response = self._helper(
            "install",
            public_addresses=[address for address in self.policy.public_addresses if ":" not in address],
            gateway_addresses=[address for address in self.policy.gateway_addresses if ":" not in address],
            gateway_port=self.policy.gateway_port,
            use_bridge_gateway=self.policy.gateway_host == "host.docker.internal",
        )
        self.chain = str(response["chain"])
        self.container_ip = str(response["container_ip"])
        self.gateway_ip = str(response.get("gateway_ip") or "")
        self.active = True
        return self.summary()

    def remove(self) -> dict:
        response = self._helper("remove")
        counters = str(response.get("counters") or "")
        self.container_ip = str(response.get("container_ip") or self.container_ip)
        self.gateway_ip = str(response.get("gateway_ip") or self.gateway_ip)
        self.active = False
        denied_packets, denied_bytes = _reject_counters(counters)
        return {**self.summary(), "counters": counters, "denied_packets": denied_packets, "denied_bytes": denied_bytes}

    def counters(self) -> str:
        if not self.active:
            return ""
        return str(self._helper("counters").get("counters") or "")[:5000]

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

    def _helper(self, action: str, **payload) -> dict:
        request = {
            "action": action,
            "task_id": self.task_id,
            "container_name": self.container_name,
            **payload,
        }
        result = self.run_command(
            ["sudo", "-n", REPRO_EGRESS_HELPER],
            input=json.dumps(request),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"egress helper request failed: {_helper_error(result)}")
        try:
            response = json.loads(str(result.stdout or "{}"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("egress helper returned invalid JSON") from exc
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise RuntimeError("egress helper returned an invalid response")
        return response


def _validated_public_host(url: str, *, resolver=None) -> str:
    error = PublicUrlPolicy(domain_allowlist=("github.com",)).validate(url, resolve_dns=True, resolver=resolver)
    if error:
        raise RuntimeError(f"unsafe reproduction repository URL: {error}")
    return str(urlsplit(url).hostname or "").casefold().rstrip(".")


def _reject_counters(output: str) -> tuple[int, int]:
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == "REJECT" and fields[0].isdigit() and fields[1].isdigit():
            return int(fields[0]), int(fields[1])
    return 0, 0


def _helper_error(result) -> str:
    output = str(result.stderr or result.stdout or "helper command failed").strip()
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return output[:500]
    return str(payload.get("error") or "helper command failed")[:500]
