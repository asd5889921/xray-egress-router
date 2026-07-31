from __future__ import annotations

import argparse
import json
import os
import time

from .network import NetworkManager
from .settings import Settings
from .storage import StateStore, atomic_write, exclusive_lock


def restore_network(settings: Settings) -> None:
    with exclusive_lock(settings.lock_file):
        NetworkManager(settings).apply(StateStore(settings).load())


def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "down"])
    parser.add_argument("interface")
    parser.add_argument("local_ip", nargs="?", default="")
    parser.add_argument("peer_ip", nargs="?", default="")
    args = parser.parse_args()

    settings = Settings.from_env()
    directory = settings.run_dir / "ppp"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{args.interface}.json"
    if args.action == "down":
        path.unlink(missing_ok=True)
        return

    payload = {
        "up": True,
        "role": "ingress",
        "interface": args.interface,
        "username": os.getenv("PEERNAME", os.getenv("PPP_PEERNAME", "unknown")),
        "local_ip": args.local_ip,
        "peer_ip": args.peer_ip,
        "started_epoch": time.time(),
    }
    atomic_write(path, json.dumps(payload, ensure_ascii=False) + "\n")

    # PPP reconnects restore routes and the complete TPROXY policy immediately.
    try:
        restore_network(settings)
    except Exception as exc:
        print(f"xrer: failed to restore network policy on {args.interface}: {exc}", flush=True)


if __name__ == "__main__":
    run()
