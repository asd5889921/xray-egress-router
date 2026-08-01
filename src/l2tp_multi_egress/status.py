from __future__ import annotations

import asyncio
import json
import ssl
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .models import Binding, Egress
from .settings import Settings
from .xray import XrayManager, make_outbound


class SystemStatus:
    def __init__(self, settings: Settings):
        self.settings = settings

    def service(self, name: str) -> str:
        unit = {"xray": "xrer-xray", "xrer-watchdog": "xrer-watchdog", "xl2tpd": "xl2tpd"}.get(name, name)
        if self.settings.dry_run:
            return "dry-run"
        result = subprocess.run(["systemctl", "is-active", unit], text=True, capture_output=True, timeout=5, check=False)
        return result.stdout.strip() or "unknown"

    def all(self) -> dict:
        return {
            "services": {name: self.service(name) for name in ("xl2tpd", "xray", "xrer-watchdog")},
            "xray_version": XrayManager(self.settings).version(),
        }

    def restart(self, name: str) -> None:
        allowed = {"xl2tpd", "xray", "xrer-watchdog"}
        if name not in allowed:
            raise ValueError("不允许操作该服务")
        if self.settings.dry_run:
            return
        unit = {"xray": "xrer-xray", "xrer-watchdog": "xrer-watchdog", "xl2tpd": "xl2tpd"}[name]
        result = subprocess.run(["systemctl", "restart", unit], text=True, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"重启 {name} 失败")


async def test_egress(settings: Settings, egress: Egress) -> dict:
    started = time.perf_counter()
    if settings.dry_run:
        await asyncio.sleep(0.01)
        return {"ok": True, "latency_ms": 10, "detail": "dry-run"}
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    binding = Binding(id="connectivity-test", source_cidr="192.0.2.0/24", egress_id=egress.id, tproxy_port=12345, mark=32768)
    outbound = make_outbound(binding, egress)
    outbound["tag"] = "tested-egress"
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{"tag": "test-in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound],
        "routing": {"rules": [{"type": "field", "inboundTag": ["test-in"], "outboundTag": "tested-egress"}]},
    }
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="xrer-test-") as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            process = await asyncio.create_subprocess_exec(str(settings.xray_binary), "run", "-config", str(path), stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            await asyncio.sleep(0.35)
            if process.returncode is not None:
                error = (await process.stderr.read()).decode(errors="replace").strip()
                raise RuntimeError(f"Xray startup failed: {error[-500:] or 'process exited'}")
            ready_at = time.perf_counter()
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 5)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                raise RuntimeError("本地测试入口握手失败")
            host = b"www.gstatic.com"
            connect_started = time.perf_counter()
            writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (443).to_bytes(2, "big"))
            await writer.drain()
            response = await asyncio.wait_for(reader.readexactly(4), 8)
            if response[1] != 0:
                raise RuntimeError(f"代理连接目标失败，SOCKS 状态码 {response[1]}")
            atyp = response[3]
            length = 4 if atyp == 1 else 16 if atyp == 4 else (await reader.readexactly(1))[0]
            await reader.readexactly(length + 2)
            tls_started = time.perf_counter()
            context = ssl.create_default_context()
            await writer.start_tls(context, server_hostname="www.gstatic.com")
            writer.write(b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), 10)
            finished_at = time.perf_counter()
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except asyncio.TimeoutError:
                # The HTTP response is already received; some proxy servers
                # keep the TLS close-notify open longer than the probe.
                pass
            ok = line.startswith(b"HTTP/")
            return {
                "ok": ok,
                # Keep latency focused on the real proxy request. Starting a
                # temporary Xray process is reported separately below.
                "latency_ms": round((finished_at - ready_at) * 1000),
                "startup_ms": round((ready_at - started) * 1000),
                "request_ms": round((finished_at - ready_at) * 1000),
                "tcp_connect_ms": round((finished_at - connect_started) * 1000),
                "tls_http_ms": round((finished_at - tls_started) * 1000),
                "detail": line.decode(errors="replace").strip(),
            }
    except Exception as exc:
        failed_at = time.perf_counter()
        return {
            "ok": False,
            "latency_ms": round((failed_at - started) * 1000),
            "startup_ms": round((failed_at - started) * 1000),
            "request_ms": None,
            "detail": str(exc),
        }
    finally:
        if process is not None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
