from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import struct
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

from .settings import Settings
from .storage import StateStore, atomic_write


@dataclass
class InterfaceSamples:
    entries: deque[tuple[float, str]] = field(default_factory=deque)


class SourceDiagnostics:
    def __init__(self, settings: Settings, window_seconds: int | None = None, min_samples: int = 30, concentration: float = 0.9, max_entries: int | None = None):
        self.settings = settings
        self.window_seconds = window_seconds if window_seconds is not None else settings.diagnostic_window_seconds
        self.min_samples = min_samples
        self.concentration = concentration
        self.max_entries = max_entries if max_entries is not None else settings.diagnostic_max_entries
        self.samples: dict[str, InterfaceSamples] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self.traffic: dict[str, dict[str, int | float]] = {}
        self._traffic_snapshot: dict[str, tuple[float, int, int]] = {}

    def record(self, interface: str, source: str, timestamp: float | None = None) -> None:
        address = ipaddress.ip_address(source)
        # Public transport addresses add noise and are not useful for the
        # Panabit source-route diagnosis. Keep only private IPv4 client IPs.
        if address.version != 4 or not address.is_private:
            return
        bucket = self.samples.setdefault(interface, InterfaceSamples())
        bucket.entries.append((timestamp or time.time(), source))
        while len(bucket.entries) > self.max_entries:
            bucket.entries.popleft()
        self._trim(bucket)

    def record_traffic(self, source: str, destination: str, byte_count: int, timestamp: float | None = None) -> None:
        """Accumulate inner IPv4 payload by private client address."""
        now = timestamp or time.time()
        for address, direction in ((source, "upstream"), (destination, "downstream")):
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.version != 4 or not parsed.is_private:
                continue
            entry = self.traffic.setdefault(address, {"upstream": 0, "downstream": 0, "last_seen": now})
            entry[direction] = int(entry[direction]) + max(0, byte_count)
            entry["last_seen"] = now

    def traffic_rates(self, timestamp: float | None = None, active_window_seconds: int = 10) -> list[dict]:
        now = timestamp or time.time()
        rows = []
        for address, entry in list(self.traffic.items()):
            if now - float(entry["last_seen"]) > active_window_seconds:
                self.traffic.pop(address, None)
                self._traffic_snapshot.pop(address, None)
                continue
            upstream = int(entry["upstream"])
            downstream = int(entry["downstream"])
            previous = self._traffic_snapshot.get(address)
            if previous is None:
                upstream_bps = downstream_bps = 0
            else:
                previous_time, previous_upstream, previous_downstream = previous
                elapsed = max(now - previous_time, 0.001)
                upstream_bps = max(0, round((upstream - previous_upstream) / elapsed))
                downstream_bps = max(0, round((downstream - previous_downstream) / elapsed))
            self._traffic_snapshot[address] = (now, upstream, downstream)
            rows.append({"source_ip": address, "upstream_bps": upstream_bps, "downstream_bps": downstream_bps})
        return sorted(rows, key=lambda item: ipaddress.ip_address(item["source_ip"]))

    def _trim(self, bucket: InterfaceSamples) -> None:
        cutoff = time.time() - self.window_seconds
        while bucket.entries and bucket.entries[0][0] < cutoff:
            bucket.entries.popleft()

    def report(self, interface: str, peer_ip: str | None = None) -> dict:
        bucket = self.samples.setdefault(interface, InterfaceSamples())
        self._trim(bucket)
        counts = Counter(source for _, source in bucket.entries)
        total = sum(counts.values())
        top_ip, top_count = counts.most_common(1)[0] if counts else (None, 0)
        ratio = top_count / total if total else 0.0
        nat_suspected = bool(total >= self.min_samples and peer_ip and top_ip == peer_ip and ratio >= self.concentration)
        networks = sorted({str(ipaddress.ip_network(f"{ip}/24", strict=False)) for ip in counts if ipaddress.ip_address(ip).version == 4})
        return {
            "interface": interface,
            "sample_count": total,
            "unique_sources": len(counts),
            "top_source": top_ip,
            "top_ratio": round(ratio, 4),
            "observed_networks": networks,
            "sources": dict(counts.most_common(20)),
            "nat_suspected": nat_suspected,
            "warning": "检测到疑似NAT模式，请确认panabit已切换为路由模式" if nat_suspected else None,
        }

    async def synchronize_interfaces(self, interfaces: list[str]) -> None:
        desired = set(interfaces)
        for name in list(self._tasks):
            if name not in desired:
                self._tasks.pop(name).cancel()
                self.samples.pop(name, None)
        for name in desired:
            if name not in self._tasks or self._tasks[name].done():
                self._tasks[name] = asyncio.create_task(self._capture(name), name=f"capture-{name}")

    async def _capture(self, interface: str) -> None:
        if os.name == "nt" or self.settings.dry_run:
            return
        # SOCK_DGRAM removes the link-layer header. This matters on PPP links,
        # whose frame layout is not the 14-byte Ethernet layout.
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        sock.setblocking(False)
        try:
            sock.bind((interface, 0))
        except OSError:
            # PPP can disappear between the status scan and this task during
            # reconnects. This is expected and should not log a traceback.
            sock.close()
            return
        loop = asyncio.get_running_loop()
        try:
            while True:
                packet = await loop.sock_recv(sock, 65535)
                details = self._ipv4_details(packet)
                if details:
                    source, destination, byte_count = details
                    self.record(interface, source)
                    self.record_traffic(source, destination, byte_count)
        finally:
            sock.close()

    @staticmethod
    def _ipv4_source(packet: bytes) -> str | None:
        details = SourceDiagnostics._ipv4_details(packet)
        return details[0] if details else None

    @staticmethod
    def _ipv4_details(packet: bytes) -> tuple[str, str, int] | None:
        if len(packet) < 20 or packet[0] >> 4 != 4:
            return None
        length = int.from_bytes(packet[2:4], "big") or len(packet)
        return socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20]), min(length, len(packet))


class PPPMonitor:
    def __init__(self, settings: Settings, diagnostics: SourceDiagnostics):
        self.settings = settings
        self.diagnostics = diagnostics

    def _events(self) -> list[dict]:
        directory = self.settings.run_dir / "ppp"
        try:
            egress_ids = {item.id for item in StateStore(self.settings).load().egresses}
        except (OSError, ValueError):
            egress_ids = set()
        result = []
        for path in directory.glob("*.json") if directory.exists() else []:
            try:
                event = json.loads(path.read_text(encoding="utf-8"))
                # Egress PPPs are external transport details; the dashboard
                # should show only inbound Panabit/LNS connections.
                is_egress = event.get("role") == "egress" or path.stem in egress_ids
                if event.get("up") and not is_egress:
                    result.append(event)
            except (OSError, ValueError):
                continue
        return result

    @staticmethod
    def _stats(interface: str) -> tuple[int, int]:
        base = Path("/sys/class/net") / interface / "statistics"
        try:
            return int((base / "rx_bytes").read_text()), int((base / "tx_bytes").read_text())
        except (OSError, ValueError):
            return 0, 0

    def connections(self) -> list[dict]:
        now = time.time()
        result = []
        for event in self._events():
            interface = event["interface"]
            rx, tx = self._stats(interface)
            result.append({
                **event,
                "duration_seconds": max(0, int(now - event.get("started_epoch", now))),
                "rx_bytes": rx,
                "tx_bytes": tx,
                "diagnostics": self.diagnostics.report(interface, event.get("peer_ip")),
            })
        return sorted(result, key=lambda item: item["interface"])

    def live_traffic(self, state) -> list[dict]:
        bindings = [(item, ipaddress.ip_network(item.source_cidr)) for item in state.bindings if item.enabled]
        egresses = {item.id: item for item in state.egresses}
        rows = []
        for row in self.diagnostics.traffic_rates():
            source = ipaddress.ip_address(row["source_ip"])
            binding = next((item for item, network in bindings if source in network), None)
            egress = egresses.get(binding.egress_id) if binding else None
            rows.append({
                **row,
                "source_cidr": binding.source_cidr if binding else None,
                "egress": {"id": egress.id, "name": egress.name, "type": egress.type.value} if egress else None,
            })
        return rows

    async def refresh_capture(self) -> None:
        await self.diagnostics.synchronize_interfaces([x["interface"] for x in self._events()])
