from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from collections import defaultdict

from .models import AppState
from .settings import Settings


TABLE = "xrer_traffic"
FAMILY = "inet"
ACTIVE_TIMEOUT_SECONDS = 15


class KernelTraffic:
    """Read per-client byte counters maintained by nftables in the kernel."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._snapshots: dict[str, tuple[float, int, int]] = {}

    def _run(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        if self.settings.dry_run:
            return subprocess.CompletedProcess(args, 0, "{}", "")
        return subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=10, check=False)

    def _checked(self, args: list[str], stdin: str | None = None) -> None:
        result = self._run(args, stdin)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip() or "nftables command failed")

    @staticmethod
    def _base_script() -> str:
        return f"""
table {FAMILY} {TABLE} {{
  set upstream {{
    type ipv4_addr
    flags dynamic,timeout
    timeout {ACTIVE_TIMEOUT_SECONDS}s
    counter
  }}
  set downstream {{
    type ipv4_addr
    flags dynamic,timeout
    timeout {ACTIVE_TIMEOUT_SECONDS}s
    counter
  }}
  chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
  }}
  chain output {{
    type filter hook output priority mangle; policy accept;
  }}
}}
"""

    def apply(self, state: AppState) -> bool:
        """Converge only the observation rules; preserve active counters."""
        if self.settings.dry_run:
            return True
        try:
            exists = self._run(["nft", "list", "table", FAMILY, TABLE])
            if exists.returncode:
                self._checked(["nft", "-f", "-"], self._base_script())
            lines = [
                f"flush chain {FAMILY} {TABLE} prerouting",
                f"flush chain {FAMILY} {TABLE} output",
            ]
            for binding in state.bindings:
                if not binding.enabled:
                    continue
                lines.extend((
                    f"add rule {FAMILY} {TABLE} prerouting iifname \"ppp*\" ip saddr {binding.source_cidr} update @upstream {{ ip saddr timeout {ACTIVE_TIMEOUT_SECONDS}s }}",
                    f"add rule {FAMILY} {TABLE} output oifname \"ppp*\" ip daddr {binding.source_cidr} update @downstream {{ ip daddr timeout {ACTIVE_TIMEOUT_SECONDS}s }}",
                ))
            self._checked(["nft", "-f", "-"], "\n".join(lines) + "\n")
            return True
        except (OSError, RuntimeError):
            return False

    @staticmethod
    def _counters(payload: dict) -> dict[str, int]:
        result: dict[str, int] = {}
        for item in payload.get("nftables", []):
            for element in item.get("set", {}).get("elem", []):
                entry = element.get("elem", {})
                address = entry.get("val")
                counter = entry.get("counter", {})
                if isinstance(address, str) and isinstance(counter.get("bytes"), int):
                    result[address] = counter["bytes"]
        return result

    def _set_counters(self, name: str) -> dict[str, int]:
        result = self._run(["nft", "-j", "list", "set", FAMILY, TABLE, name])
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip() or "nftables statistics unavailable")
        try:
            return self._counters(json.loads(result.stdout))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("invalid nftables statistics output") from exc

    def rows(self, state: AppState, timestamp: float | None = None) -> list[dict]:
        if self.settings.dry_run:
            return []
        now = timestamp or time.time()
        upstream = self._set_counters("upstream")
        downstream = self._set_counters("downstream")
        current = set(upstream) | set(downstream)
        rows = []
        bindings = [(item, ipaddress.ip_network(item.source_cidr)) for item in state.bindings if item.enabled]
        egresses = {item.id: item for item in state.egresses}
        for address in sorted(current, key=ipaddress.ip_address):
            upstream_bytes = upstream.get(address, 0)
            downstream_bytes = downstream.get(address, 0)
            previous = self._snapshots.get(address)
            if previous is None:
                upstream_bps = downstream_bps = 0
            else:
                previous_time, previous_upstream, previous_downstream = previous
                elapsed = max(now - previous_time, 0.001)
                upstream_bps = max(0, round((upstream_bytes - previous_upstream) / elapsed))
                downstream_bps = max(0, round((downstream_bytes - previous_downstream) / elapsed))
            self._snapshots[address] = (now, upstream_bytes, downstream_bytes)
            source = ipaddress.ip_address(address)
            binding = next((item for item, network in bindings if source in network), None)
            egress = egresses.get(binding.egress_id) if binding else None
            rows.append({
                "source_ip": address,
                "source_cidr": binding.source_cidr if binding else None,
                "egress": {"id": egress.id, "name": egress.name, "type": egress.type.value} if egress else None,
                "upstream_bps": upstream_bps,
                "downstream_bps": downstream_bps,
            })
        self._snapshots = {address: self._snapshots[address] for address in current}
        return rows
