from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from l2tp_multi_egress.diagnostics import SourceDiagnostics
from l2tp_multi_egress.main import create_app
from l2tp_multi_egress.models import AppState, Binding, Egress, ProxyType
from l2tp_multi_egress.network import iptables_restore_script
from l2tp_multi_egress.settings import Settings
from l2tp_multi_egress.ss_uri import parse_ss_uri
from l2tp_multi_egress.transaction import TransactionManager
from l2tp_multi_egress.xray import build_config


def settings(tmp_path: Path, rollback: int = 60) -> Settings:
    return Settings(tmp_path / "etc", tmp_path / "run", Path("xray"), "127.0.0.1:10085", True, "127.0.0.1", 17890, rollback)


def sample_state() -> AppState:
    return AppState(
        egresses=[Egress(id="hk", name="Hong Kong", type=ProxyType.SHADOWSOCKS, address="proxy.example", port=8388, password="secret", method="aes-256-gcm")],
        bindings=[Binding(id="group1", source_cidr="192.168.1.0/24", egress_id="hk", tproxy_port=12001, mark=32769)],
    )


def test_ss_uri_sip002_and_legacy():
    userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
    modern = parse_ss_uri(f"ss://{userinfo}@example.com:8388#HK", egress_id="hk")
    legacy = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:p@ss@[2001:db8::1]:443").decode().rstrip("=")
    old = parse_ss_uri(f"ss://{legacy}", egress_id="old")
    assert (modern.method, modern.password, modern.name) == ("aes-256-gcm", "secret", "HK")
    assert (old.address, old.port, old.password) == ("2001:db8::1", 443, "p@ss")


def test_state_rejects_overlaps():
    base = sample_state()
    with pytest.raises(ValidationError, match="来源网段重叠"):
        AppState(egresses=base.egresses, bindings=base.bindings + [Binding(id="group2", source_cidr="192.168.1.128/25", egress_id="hk", tproxy_port=12002, mark=32770)])


def test_generated_xray_and_iptables_are_udp_tproxy_only():
    state = sample_state()
    config = build_config(state, "127.0.0.1:10085")
    inbound = config["inbounds"][0]
    assert inbound["settings"]["network"] == "tcp,udp"
    assert inbound["streamSettings"]["sockopt"]["tproxy"] == "tproxy"
    assert config["outbounds"][0]["mux"]["enabled"] is False
    rules = iptables_restore_script(state)
    assert "-p udp -j TPROXY" in rules
    assert "-i ppp+" in rules
    assert "--dport 1701 -j RETURN" in rules
    assert "MASQUERADE" not in rules and "SNAT" not in rules and "REDIRECT" not in rules


def test_only_xray_egress_types_are_accepted():
    assert {item.value for item in ProxyType} == {"shadowsocks", "socks", "http"}
    with pytest.raises(ValidationError):
        Egress.model_validate({"id": "bad", "name": "bad", "type": "l2tp", "address": "x", "port": 1701})


def test_nat_diagnostic_requires_peer_concentration(tmp_path):
    diag = SourceDiagnostics(settings(tmp_path), min_samples=10, concentration=0.9)
    for _ in range(9):
        diag.record("ppp0", "10.200.0.10")
    diag.record("ppp0", "192.168.1.2")
    report = diag.report("ppp0", "10.200.0.10")
    assert report["nat_suspected"] is True


def test_source_diagnostics_keeps_only_private_ipv4(tmp_path):
    diag = SourceDiagnostics(settings(tmp_path), min_samples=1, max_entries=3)
    diag.record("ppp0", "8.8.8.8")
    diag.record("ppp0", "2001:db8::1")
    diag.record("ppp0", "192.168.17.100")
    report = diag.report("ppp0", "192.168.17.100")
    assert report["sample_count"] == 1
    assert report["sources"] == {"192.168.17.100": 1}
    assert "NAT模式" in report["warning"]


def test_transaction_apply_confirm_and_rollback(tmp_path):
    cfg = settings(tmp_path)
    manager = TransactionManager(cfg)
    candidate = sample_state()
    tx = manager.apply(candidate)
    assert manager.store.load().revision == 1
    manager.rollback(tx.id)
    assert manager.store.load().revision == 0
    tx2 = manager.apply(candidate)
    manager.confirm(tx2.id)
    assert manager.pending() is None


def test_web_login_crud_and_confirmation(tmp_path):
    cfg = settings(tmp_path)
    app = create_app(cfg)
    with TestClient(app) as client:
        assert client.post("/api/initialize", json={"username": "admin", "password": "long-test-password"}).status_code == 200
        login = client.post("/api/login", json={"username": "admin", "password": "long-test-password"})
        csrf = login.json()["csrf"]
        headers = {"X-CSRF-Token": csrf}
        egress = sample_state().egresses[0].model_dump(mode="json")
        response = client.put("/api/egresses/hk", json={key: value for key, value in egress.items() if key != "id"}, headers=headers)
        assert response.status_code == 200
        txid = response.json()["transaction"]["id"]
        assert client.post(f"/api/transactions/{txid}/confirm", headers=headers).status_code == 200
        binding = sample_state().bindings[0].model_dump(mode="json")
        response = client.put("/api/bindings/group1", json=binding, headers=headers)
        assert response.status_code == 200
        txid = response.json()["transaction"]["id"]
        assert client.post(f"/api/transactions/{txid}/confirm", headers=headers).status_code == 200
        state = client.get("/api/state").json()["state"]
        assert state["bindings"][0]["source_cidr"] == "192.168.1.0/24"


def test_web_egress_ids_are_generated_and_bulk_delete(tmp_path):
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        client.post("/api/initialize", json={"username": "admin", "password": "long-test-password"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "long-test-password"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}
        payload = {"name": "Generated", "type": "socks", "address": "127.0.0.1", "port": 1080}
        created = client.post("/api/egresses", json={**payload, "id": "client-supplied"}, headers=headers)
        assert created.status_code == 200
        generated = created.json()["state"]["egresses"][0]["id"]
        assert generated.startswith("egress-") and generated != "client-supplied"
        txid = created.json()["transaction"]["id"]
        client.post(f"/api/transactions/{txid}/confirm", headers=headers)
        binding = {"id": "b", "source_cidr": "192.168.50.0/24", "egress_id": generated, "tproxy_port": 12010, "mark": 32780, "enabled": True}
        response = client.put("/api/bindings/b", json=binding, headers=headers)
        txid = response.json()["transaction"]["id"]
        client.post(f"/api/transactions/{txid}/confirm", headers=headers)
        assert client.post("/api/egresses/bulk-delete", json={"ids": [generated]}, headers=headers).status_code == 409
        removed_binding = client.post("/api/bindings/bulk-delete", json={"ids": ["b"]}, headers=headers)
        assert removed_binding.status_code == 200
        client.post(f"/api/transactions/{removed_binding.json()['transaction']['id']}/confirm", headers=headers)
        assert client.post("/api/egresses/bulk-delete", json={"ids": [generated]}, headers=headers).status_code == 200


def test_web_config_export_import_is_validated(tmp_path):
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        client.post("/api/initialize", json={"username": "admin", "password": "long-test-password"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "long-test-password"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}
        exported = client.get("/api/config/export")
        assert exported.status_code == 200
        assert exported.headers["content-disposition"].endswith('xrer-config.json"')
        backup = exported.json()
        backup["state"]["egresses"] = []
        backup["state"]["bindings"] = []
        imported = client.post("/api/config/import", json={"backup": backup}, headers=headers)
        assert imported.status_code == 200
        assert imported.json()["state"]["egresses"] == []
        client.post(f"/api/transactions/{imported.json()['transaction']['id']}/confirm", headers=headers)
        assert client.post("/api/config/import", json={"backup": {"state": {"not_state": True}}}, headers=headers).status_code == 422


def test_web_binding_internal_values_are_automatic(tmp_path):
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        client.post("/api/initialize", json={"username": "admin", "password": "long-test-password"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "long-test-password"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}
        egress = {"name": "socks", "type": "socks", "address": "127.0.0.1", "port": 1080}
        created = client.post("/api/egresses", json=egress, headers=headers).json()
        client.post(f"/api/transactions/{created['transaction']['id']}/confirm", headers=headers)
        binding = client.post("/api/bindings", json={"source_cidr": "192.168.60.0/24", "egress_id": created["state"]["egresses"][0]["id"], "enabled": True}, headers=headers)
        assert binding.status_code == 200
        item = binding.json()["state"]["bindings"][0]
        assert item["id"].startswith("group-")
        assert item["tproxy_port"] >= 12001
        assert item["mark"] >= 32769


def test_management_routes_include_all_mutating_ui_actions(tmp_path):
    app = create_app(settings(tmp_path))
    routes = {(route.path, method) for route in app.routes for method in getattr(route, "methods", set())}
    expected = {
        ("/api/bootstrap", "GET"),
        ("/api/initialize", "POST"),
        ("/api/login", "POST"),
        ("/api/logout", "POST"),
        ("/api/state", "GET"),
        ("/api/config/export", "GET"),
        ("/api/egresses", "POST"),
        ("/api/egresses/{egress_id}", "PUT"),
        ("/api/egresses/{egress_id}", "DELETE"),
        ("/api/egresses/{egress_id}/test", "POST"),
        ("/api/egresses/bulk-delete", "POST"),
        ("/api/bindings", "POST"),
        ("/api/bindings/{binding_id}", "PUT"),
        ("/api/bindings/{binding_id}", "DELETE"),
        ("/api/bindings/bulk-delete", "POST"),
        ("/api/transactions/{transaction_id}/confirm", "POST"),
        ("/api/transactions/{transaction_id}/rollback", "POST"),
        ("/api/connections", "GET"),
        ("/api/system", "GET"),
        ("/api/system/{name}/restart", "POST"),
        ("/api/parse-ss", "POST"),
        ("/api/config/import", "POST"),
        ("/api/log-settings", "PUT"),
        ("/api/log-settings", "GET"),
    }
    assert expected <= routes
