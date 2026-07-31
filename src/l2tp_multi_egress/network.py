from __future__ import annotations

import json
import re
import subprocess

from .models import AppState
from .settings import Settings

CHAIN = "XRER_TPROXY"
ROUTE_TABLE = 100
MANAGED_MARK = 0x8000


def iptables_restore_script(state: AppState) -> str:
    lines = [
        "*mangle",
        f":{CHAIN} - [0:0]",
        f"-F {CHAIN}",
        f"-A {CHAIN} -p udp --dport 1701 -j RETURN",
        f"-A {CHAIN} -d 0.0.0.0/8 -j RETURN",
        f"-A {CHAIN} -d 10.0.0.0/8 -j RETURN",
        f"-A {CHAIN} -d 100.64.0.0/10 -j RETURN",
        f"-A {CHAIN} -d 127.0.0.0/8 -j RETURN",
        f"-A {CHAIN} -d 169.254.0.0/16 -j RETURN",
        f"-A {CHAIN} -d 172.16.0.0/12 -j RETURN",
        f"-A {CHAIN} -d 192.168.0.0/16 -j RETURN",
        f"-A {CHAIN} -d 224.0.0.0/4 -j RETURN",
        f"-A {CHAIN} -d 240.0.0.0/4 -j RETURN",
    ]
    for binding in state.bindings:
        if not binding.enabled:
            continue
        for protocol in ("tcp", "udp"):
            lines.append(
                f"-A {CHAIN} -i ppp+ -s {binding.source_cidr} -p {protocol} "
                f"-j TPROXY --on-ip 127.0.0.1 --on-port {binding.tproxy_port} "
                f"--tproxy-mark {binding.mark}/0xffffffff"
            )
    lines.extend(["COMMIT", ""])
    return "\n".join(lines)


class NetworkManager:
    """Restore Panabit ingress routes and converge the Xray TPROXY rules."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def _run(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        if self.settings.dry_run:
            return subprocess.CompletedProcess(args, 0, "dry-run", "")
        return subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=20, check=False)

    def _checked(self, args: list[str], stdin: str | None = None) -> None:
        result = self._run(args, stdin)
        if result.returncode:
            raise RuntimeError(f"command failed {' '.join(args)}: {(result.stderr or result.stdout).strip()}")

    def ensure_source_routes(self, state: AppState) -> None:
        """Restore each Panabit source CIDR after PPP reconnects."""
        result = self._run(["ip", "-o", "link", "show", "up"])
        interfaces = re.findall(r"\d+: (ppp\d+):", result.stdout)
        if self.settings.dry_run or not interfaces:
            return
        runtime = self.settings.run_dir / "ppp"
        ingress = []
        for path in runtime.glob("*.json") if runtime.exists() else []:
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                if item.get("role") == "ingress" and item.get("interface") in interfaces:
                    ingress.append(item["interface"])
            except (OSError, ValueError):
                continue
        interface = ingress[0] if len(ingress) == 1 else (interfaces[0] if len(interfaces) == 1 else None)
        if not interface:
            return
        for binding in state.bindings:
            if binding.enabled:
                self._checked(["ip", "route", "replace", binding.source_cidr, "dev", interface])

    def ensure_policy_route(self, _: AppState) -> None:
        self._checked(["ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", str(ROUTE_TABLE)])
        result = self._run(["ip", "rule", "show"])
        needle = f"fwmark 0x8000/0x8000 lookup {ROUTE_TABLE}"
        if needle not in result.stdout:
            self._checked(["ip", "rule", "add", "fwmark", f"{MANAGED_MARK}/{MANAGED_MARK}", "table", str(ROUTE_TABLE), "priority", "30000"])

    def apply(self, state: AppState) -> None:
        self.ensure_source_routes(state)
        self.ensure_policy_route(state)
        script = iptables_restore_script(state)
        self._checked(["iptables-restore", "--noflush", "--test"], script)
        self._checked(["iptables-restore", "--noflush"], script)
        check = self._run(["iptables", "-t", "mangle", "-C", "PREROUTING", "-i", "ppp+", "-j", CHAIN])
        if check.returncode:
            self._checked(["iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-i", "ppp+", "-j", CHAIN])
