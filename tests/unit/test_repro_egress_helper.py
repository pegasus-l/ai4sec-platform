from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


HELPER_PATH = Path(__file__).parents[2] / "configs" / "repro-egress-helper" / "ai4sec-repro-egress-helper"


def _load_helper():
    loader = importlib.machinery.SourceFileLoader("ai4sec_repro_egress_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_helper_rejects_private_and_unbounded_destinations() -> None:
    helper = _load_helper()

    with pytest.raises(helper.HelperError, match="non-public IPv4"):
        helper.validate_public_addresses(["127.0.0.1"], "public_addresses")
    with pytest.raises(helper.HelperError, match="bounded list"):
        helper.validate_public_addresses(["93.184.216.34"] * 257, "public_addresses")


def test_helper_rejects_wrong_container_ownership(monkeypatch) -> None:
    helper = _load_helper()
    inspected = [{
        "Config": {"Labels": {
            helper.RESOURCE_LABEL: helper.EXPECTED_RESOURCE,
            helper.TASK_LABEL: "8",
            helper.PROFILE_LABEL: "nested_docker",
        }},
        "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.9"}}},
    }]
    monkeypatch.setattr(helper, "command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "run", lambda _command: SimpleNamespace(stdout=__import__("json").dumps(inspected)))

    with pytest.raises(helper.HelperError, match="not owned"):
        helper.inspect_container("repro-7", 7)


def test_helper_rejects_stopped_container_without_bridge_ip(monkeypatch) -> None:
    helper = _load_helper()
    inspected = [{
        "Config": {"Labels": {
            helper.RESOURCE_LABEL: helper.EXPECTED_RESOURCE,
            helper.TASK_LABEL: "7",
            helper.PROFILE_LABEL: "nested_docker",
        }},
        "NetworkSettings": {"Networks": {"bridge": {"IPAddress": ""}}},
    }]
    monkeypatch.setattr(helper, "command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "run", lambda _command: SimpleNamespace(stdout=__import__("json").dumps(inspected)))

    with pytest.raises(helper.HelperError, match="isolated Docker bridge IPv4"):
        helper.inspect_container("repro-7", 7)


def test_helper_install_restricts_gateway_port_and_rule_shape(monkeypatch) -> None:
    helper = _load_helper()
    commands: list[list[str]] = []
    request = {
        "action": "install",
        "task_id": 7,
        "container_name": "repro-7",
        "public_addresses": ["93.184.216.34"],
        "gateway_addresses": [],
        "gateway_port": 8000,
        "use_bridge_gateway": True,
    }
    monkeypatch.setattr(helper, "command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "inspect_container", lambda *_args: {"container_ip": "172.17.0.9"})
    monkeypatch.setattr(helper, "bridge_gateway", lambda: "172.17.0.1")
    monkeypatch.setattr(helper, "chain_exists", lambda _chain: False)
    monkeypatch.setattr(helper, "run", lambda command: commands.append(command) or SimpleNamespace(stdout=""))

    response = helper.install(request, {"allowed_gateway_ports": (8000,)})

    assert response["container_ip"] == "172.17.0.9"
    assert ["/usr/bin/iptables", "-w", "5", "-A", response["chain"], "-j", "REJECT"] in commands
    assert ["/usr/bin/iptables", "-w", "5", "-I", "DOCKER-USER", "1", "-s", "172.17.0.9", "-j", response["chain"]] in commands
    assert all("127.0.0.1" not in command for command in commands)

    with pytest.raises(helper.HelperError, match="port is not allowed"):
        helper.install({**request, "gateway_port": 2375}, {"allowed_gateway_ports": (8000,)})


def test_helper_remove_cleans_chain_when_stopped_container_has_no_ip(monkeypatch) -> None:
    helper = _load_helper()
    removed: list[str] = []
    monkeypatch.setattr(helper, "inspect_container", lambda *_args: (_ for _ in ()).throw(helper.HelperError("no bridge IP")))
    monkeypatch.setattr(helper, "chain_exists", lambda _chain: True)
    monkeypatch.setattr(helper, "read_counters", lambda _chain: "1 2 REJECT")
    monkeypatch.setattr(helper, "remove_chain", lambda chain: removed.append(chain))

    result = helper.remove({"task_id": 7, "container_name": "repro-7"})

    assert removed == [result["chain"]]
    assert result["container_ip"] == ""


def test_helper_requires_configured_sudo_caller(monkeypatch) -> None:
    helper = _load_helper()
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1001")

    with pytest.raises(helper.HelperError, match="not the configured"):
        helper.validate_caller({"allowed_uid": 1000})


def test_helper_preflight_rejects_unconfigured_gateway_port() -> None:
    helper = _load_helper()

    with pytest.raises(helper.HelperError, match="not allowed by root configuration"):
        helper.preflight({"gateway_port": 9000}, {"allowed_uid": 1000, "allowed_gateway_ports": (8000,)})


def test_helper_rejects_command_line_arguments(monkeypatch, capsys) -> None:
    helper = _load_helper()
    monkeypatch.setattr(helper.sys, "argv", ["ai4sec-repro-egress-helper", "install"])

    assert helper.main() == 2
    assert "does not accept command-line arguments" in capsys.readouterr().err
