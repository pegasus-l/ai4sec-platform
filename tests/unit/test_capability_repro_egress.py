from __future__ import annotations

import json
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
    requests: list[dict] = []

    def fake_run(command, **kwargs):
        assert command[0:2] == ["sudo", "-n"]
        request = json.loads(kwargs["input"])
        requests.append(request)
        if request["action"] == "install":
            response = {"ok": True, "chain": "A4R_7_123456", "container_ip": "172.17.0.9", "gateway_ip": "172.17.0.1"}
        else:
            response = {
                "ok": True,
                "chain": "A4R_7_123456",
                "container_ip": "172.17.0.9",
                "gateway_ip": "172.17.0.1",
                "counters": "pkts bytes target prot opt in out source destination\n12 640 REJECT all -- * * 0.0.0.0/0 0.0.0.0/0\n",
            }
        return SimpleNamespace(returncode=0, stdout=json.dumps(response), stderr="")

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
    assert requests[0]["action"] == "install"
    assert requests[0]["task_id"] == 7
    assert requests[0]["container_name"] == "repro"
    assert requests[0]["public_addresses"] == ["93.184.216.34"]
    assert requests[0]["gateway_port"] == 8000
    assert requests[0]["use_bridge_gateway"] is True
    assert requests[1]["action"] == "remove"
    assert audit["denied_packets"] == 12
    assert audit["denied_bytes"] == 640


def test_repro_egress_preflight_fails_closed_without_docker_user_chain() -> None:
    def fake_run(command, **kwargs):
        assert json.loads(kwargs["input"]) == {"action": "preflight"}
        return SimpleNamespace(returncode=2, stdout="", stderr='{"ok": false, "error": "DOCKER-USER unavailable"}')

    with pytest.raises(RuntimeError, match="DOCKER-USER unavailable"):
        validate_repro_egress_runtime(fake_run)


def _public_resolver(host, port, *, type=socket.SOCK_STREAM):
    return _resolver_result("93.184.216.34")


def _resolver_result(address: str):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]
