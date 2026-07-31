from __future__ import annotations

import argparse
import json
import os
import time

from .settings import Settings
from .storage import StateStore, atomic_write


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

    # PPP reconnects must restore the Panabit source routes immediately.
    try:
        from .network import NetworkManager

        manager = NetworkManager(settings)
        state = StateStore(settings).load()
        manager.ensure_source_routes(state)
        manager.ensure_policy_route(state)
    except Exception as exc:
        print(f"xrer: failed to restore source routes on {args.interface}: {exc}", flush=True)


if __name__ == "__main__":
    run()
