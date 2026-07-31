from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from .models import AppState, Binding, Egress, ProxyType
from .settings import Settings
from .storage import atomic_write


API_TAG = "xrer-api"
REQUIRED_XRAY_VERSION = "26.6.27"


def inbound_tag(binding: Binding) -> str:
    return f"xrer-in-{binding.id}"


def outbound_tag(binding: Binding) -> str:
    return f"xrer-out-{binding.id}"


def make_inbound(binding: Binding) -> dict:
    return {
        "tag": inbound_tag(binding),
        "listen": "0.0.0.0",
        "port": binding.tproxy_port,
        "protocol": "dokodemo-door",
        "settings": {"network": "tcp,udp", "followRedirect": True},
        "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }


def make_outbound(binding: Binding, egress: Egress) -> dict:
    tag = outbound_tag(binding)
    if egress.type == ProxyType.SHADOWSOCKS:
        settings = {
            "servers": [{
                "address": egress.address,
                "port": egress.port,
                "method": egress.method,
                "password": egress.password,
                "uot": True,
            }]
        }
        protocol = "shadowsocks"
    elif egress.type == ProxyType.SOCKS:
        server: dict = {"address": egress.address, "port": egress.port}
        if egress.username:
            server["users"] = [{"user": egress.username, "pass": egress.password or ""}]
        settings, protocol = {"servers": [server]}, "socks"
    elif egress.type == ProxyType.HTTP:
        server = {"address": egress.address, "port": egress.port}
        if egress.username:
            server["users"] = [{"user": egress.username, "pass": egress.password or ""}]
        settings, protocol = {"servers": [server]}, "http"
    else:
        raise ValueError(f"unsupported egress type: {egress.type}")
    return {
        "tag": tag,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": {"sockopt": {"mark": 255}},
        "mux": {"enabled": False},
    }


def build_config(state: AppState, api_address: str, loglevel: str = "error") -> dict:
    egresses = {x.id: x for x in state.egresses}
    enabled = [x for x in state.bindings if x.enabled]
    inbounds = [make_inbound(x) for x in enabled]
    outbounds = [make_outbound(x, egresses[x.egress_id]) for x in enabled]
    outbounds.extend([
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "blocked", "protocol": "blackhole"},
    ])
    rules = [{"type": "field", "inboundTag": [inbound_tag(x)], "outboundTag": outbound_tag(x)} for x in enabled]
    config: dict = {
        "log": {"loglevel": loglevel if loglevel in {"error", "warning", "info", "debug", "none"} else "error"},
        "api": {"tag": API_TAG, "listen": api_address, "services": ["HandlerService", "RoutingService", "StatsService"]},
        "stats": {},
        "policy": {"system": {"statsInboundUplink": True, "statsInboundDownlink": True, "statsOutboundUplink": True, "statsOutboundDownlink": True}},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    if state.fake_dns:
        config["fakedns"] = [{"ipPool": "198.18.0.0/15", "poolSize": 65535}]
        config["dns"] = {"servers": ["fakedns"]}
        for item in inbounds:
            if item.get("tag", "").startswith("xrer-in-"):
                item["sniffing"]["destOverride"].append("fakedns")
    return config


class XrayManager:
    def __init__(self, settings: Settings):
        self.settings = settings

    def write_config(self, state: AppState, name: str = "config.json") -> Path:
        path = self.settings.xray_dir / name
        atomic_write(path, json.dumps(build_config(state, self.settings.xray_api, self.settings.xray_log_level), ensure_ascii=False, indent=2) + "\n")
        return path

    def _run(self, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        if self.settings.dry_run:
            return subprocess.CompletedProcess(args, 0, "dry-run", "")
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)

    def validate(self, config_path: Path) -> None:
        result = self._run([str(self.settings.xray_binary), "run", "-test", "-config", str(config_path)])
        if result.returncode:
            raise RuntimeError(f"Xray 配置校验失败: {(result.stderr or result.stdout).strip()}")

    def version(self) -> str:
        result = self._run([str(self.settings.xray_binary), "version"])
        if result.returncode:
            return "unavailable"
        first = result.stdout.splitlines()[0] if result.stdout else "unknown"
        return first.strip()

    def require_version(self) -> str:
        version = self.version()
        if self.settings.dry_run:
            return f"Xray {REQUIRED_XRAY_VERSION} (dry-run)"
        if f"Xray {REQUIRED_XRAY_VERSION}" not in version:
            raise RuntimeError(f"Xray 版本必须为 {REQUIRED_XRAY_VERSION}，当前检测结果: {version}")
        return version

    def _api(self, command: str, *args: str) -> None:
        result = self._run([str(self.settings.xray_binary), "api", command, "--server", self.settings.xray_api, *args])
        if result.returncode:
            raise RuntimeError(f"Xray API {command} 失败: {(result.stderr or result.stdout).strip()}")

    def replace_routing(self, state: AppState) -> None:
        rules = [
            {"type": "field", "inboundTag": [inbound_tag(item)], "outboundTag": outbound_tag(item)}
            for item in state.bindings if item.enabled
        ]
        path = self.settings.run_dir / "routing.json"
        atomic_write(path, json.dumps({"routing": {"domainStrategy": "AsIs", "rules": rules}}))
        self._api("adrules", str(path))

    def restart_with(self, state: AppState) -> None:
        self.write_config(state)
        result = self._run(["systemctl", "restart", "xrer-xray"], timeout=30)
        if result.returncode:
            raise RuntimeError(f"切换 FakeDNS 时重启 Xray 失败: {(result.stderr or result.stdout).strip()}")
        if not self.settings.dry_run:
            time.sleep(0.5)
            self.require_version()

    def apply_dynamic(self, old: AppState, new: AppState) -> None:
        """Replace managed handlers through HandlerService without restarting Xray."""
        old_bindings = {x.id: x for x in old.bindings if x.enabled}
        new_bindings = {x.id: x for x in new.bindings if x.enabled}
        old_egresses = {x.id: x for x in old.egresses}
        new_egresses = {x.id: x for x in new.egresses}
        changed = {
            key for key in old_bindings.keys() | new_bindings.keys()
            if old_bindings.get(key) != new_bindings.get(key)
            or (key in old_bindings and old_egresses.get(old_bindings[key].egress_id) != new_egresses.get(new_bindings.get(key, old_bindings[key]).egress_id))
        }
        for key in changed:
            old_binding = old_bindings.get(key)
            if old_binding:
                self._api("rmi", inbound_tag(old_binding))
                self._api("rmo", outbound_tag(old_binding))
        try:
            for key in changed:
                binding = new_bindings.get(key)
                if not binding:
                    continue
                inbound_file = self.settings.run_dir / f"{inbound_tag(binding)}.json"
                outbound_file = self.settings.run_dir / f"{outbound_tag(binding)}.json"
                atomic_write(inbound_file, json.dumps({"inbounds": [make_inbound(binding)]}))
                atomic_write(outbound_file, json.dumps({"outbounds": [make_outbound(binding, new_egresses[binding.egress_id])] }))
                self._api("adi", str(inbound_file))
                self._api("ado", str(outbound_file))
            self.replace_routing(new)
        except Exception:
            self._restore_handlers(old, changed)
            self.replace_routing(old)
            raise
        finally:
            self._cleanup_handler_files(changed)

    def _cleanup_handler_files(self, ids: set[str]) -> None:
        for key in ids:
            for prefix in ("xrer-in-", "xrer-out-", "restore-xrer-in-", "restore-xrer-out-"):
                try:
                    (self.settings.run_dir / f"{prefix}{key}.json").unlink(missing_ok=True)
                except OSError:
                    pass

    def _restore_handlers(self, state: AppState, ids: set[str]) -> None:
        bindings = {x.id: x for x in state.bindings if x.enabled}
        egresses = {x.id: x for x in state.egresses}
        for key in ids:
            binding = bindings.get(key)
            if not binding:
                continue
            inbound_file = self.settings.run_dir / f"restore-{inbound_tag(binding)}.json"
            outbound_file = self.settings.run_dir / f"restore-{outbound_tag(binding)}.json"
            atomic_write(inbound_file, json.dumps({"inbounds": [make_inbound(binding)]}))
            atomic_write(outbound_file, json.dumps({"outbounds": [make_outbound(binding, egresses[binding.egress_id])] }))
            self._api("adi", str(inbound_file))
            self._api("ado", str(outbound_file))
