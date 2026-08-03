from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from ai4sec_platform.domains.capabilities.egress import DockerEgressGuard, build_repro_egress_policy, validate_repro_egress_runtime


def test_repro_egress_policy_allows_public_repo_and_gateway_exception() -> None:
    policy = build_repro_egress_policy(
        "https://github.com/example/repo",
        "http://host.docker.internal:8000/api/model-gateway/v1",
        resolver=_public_resolver,
    )

    assert "github.com" in policy.domains
    assert "pypi.org" in policy.domains
    assert policy.gateway_host == "host.docker.internal"
    assert policy.gateway_port == 8000
    assert policy.gateway_addresses == ()
    assert policy.public_addresses == ("93.184.216.34",)
    assert ("github.com", "93.184.216.34") in policy.host_addresses


def test_repro_egress_policy_includes_task_approved_domain() -> None:
    policy = build_repro_egress_policy(
        "https://github.com/example/repo",
        "http://host.docker.internal:8000/api/model-gateway/v1",
        approved_domains=("api.example.com",),
        resolver=_public_resolver,
    )

    assert "api.example.com" in policy.domains
    assert ("api.example.com", "93.184.216.34") in policy.host_addresses


def test_repro_egress_policy_rejects_private_repo_resolution() -> None:
    with pytest.raises(RuntimeError, match="unsafe reproduction repository URL"):
        build_repro_egress_policy(
            "https://github.com/example/repo",
            "http://host.docker.internal:8000/api/model-gateway/v1",
            resolver=lambda *_args, **_kwargs: _resolver_result("127.0.0.1"),
        )


def test_docker_egress_guard_installs_default_reject_and_cleans_up() -> None:
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        if command[:3] == ["docker", "inspect", "--format"]:
            return SimpleNamespace(returncode=0, stdout="172.17.0.9\n", stderr="")
        if command[:3] == ["docker", "network", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="172.17.0.1\n", stderr="")
        if command[:3] == ["iptables", "-L", "A4R_7_123456"]:
            return SimpleNamespace(returncode=0, stdout="pkts bytes target prot opt in out source destination\n12 640 REJECT all -- * * 0.0.0.0/0 0.0.0.0/0\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    policy = build_repro_egress_policy(
        "https://github.com/example/repo",
        "http://host.docker.internal:8000/api/model-gateway/v1",
        resolver=_public_resolver,
    )
    guard = DockerEgressGuard(task_id=7, container_name="repro", policy=policy, run_command=fake_run)
    guard.chain = "A4R_7_123456"
    summary = guard.install()
    audit = guard.remove()

    assert summary["container_ip"] == "172.17.0.9"
    assert ["iptables", "-A", guard.chain, "-j", "REJECT"] in commands
    assert ["iptables", "-I", "DOCKER-USER", "1", "-s", "172.17.0.9", "-j", guard.chain] in commands
    assert ["iptables", "-A", guard.chain, "-d", "172.17.0.1", "-p", "tcp", "--dport", "8000", "-j", "ACCEPT"] in commands
    assert audit["denied_packets"] == 12
    assert audit["denied_bytes"] == 640
    assert ["iptables", "-X", guard.chain] in commands


def test_repro_egress_preflight_fails_closed_without_docker_user_chain() -> None:
    def fake_run(command, **_kwargs):
        return SimpleNamespace(returncode=1 if command[0] == "iptables" else 0, stdout="", stderr="missing")

    with pytest.raises(RuntimeError, match="egress enforcement is unavailable"):
        validate_repro_egress_runtime(fake_run)


def _public_resolver(host, port, *, type=socket.SOCK_STREAM):
    return _resolver_result("93.184.216.34")


def _resolver_result(address: str):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]
