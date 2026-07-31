from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    config_dir: Path
    run_dir: Path
    xray_binary: Path
    xray_api: str
    dry_run: bool
    listen_host: str
    listen_port: int
    rollback_seconds: int
    diagnostic_window_seconds: int = 300
    diagnostic_max_entries: int = 1000
    xray_log_level: str = "error"
    log_retention_days: int = 7

    @classmethod
    def from_env(cls) -> "Settings":
        config_dir = Path(os.getenv("XRER_CONFIG_DIR", "/etc/xray-egress-router"))
        preferences: dict = {}
        try:
            import json
            preferences = json.loads((config_dir / "preferences.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            pass
        return cls(
            config_dir=config_dir,
            run_dir=Path(os.getenv("XRER_RUN_DIR", "/run/xray-egress-router")),
            xray_binary=Path(os.getenv("XRER_XRAY_BINARY", "/usr/local/bin/xray")),
            xray_api=os.getenv("XRER_XRAY_API", "127.0.0.1:10085"),
            dry_run=os.getenv("XRER_DRY_RUN", "0") == "1",
            listen_host=os.getenv("XRER_LISTEN_HOST", "127.0.0.1"),
            listen_port=int(os.getenv("XRER_LISTEN_PORT", "17890")),
            rollback_seconds=int(os.getenv("XRER_ROLLBACK_SECONDS", "60")),
            diagnostic_window_seconds=max(60, int(os.getenv("XRER_DIAGNOSTIC_WINDOW_SECONDS", "300"))),
            diagnostic_max_entries=max(100, int(os.getenv("XRER_DIAGNOSTIC_MAX_ENTRIES", "1000"))),
            xray_log_level=os.getenv("XRER_XRAY_LOG_LEVEL", str(preferences.get("xray_log_level", "error"))).lower(),
            log_retention_days=max(0, int(os.getenv("XRER_LOG_RETENTION_DAYS", str(preferences.get("log_retention_days", 7))))),
        )

    @property
    def state_file(self) -> Path:
        return self.config_dir / "state.json"

    @property
    def history_dir(self) -> Path:
        return self.config_dir / "history"

    @property
    def xray_dir(self) -> Path:
        return self.config_dir / "xray_config"

    @property
    def log_dir(self) -> Path:
        return self.config_dir / "logs"

    @property
    def pending_file(self) -> Path:
        return self.run_dir / "pending-transaction.json"

    @property
    def lock_file(self) -> Path:
        return self.run_dir / "apply.lock"

    def ensure_dirs(self) -> None:
        for path in (self.config_dir, self.run_dir, self.history_dir, self.xray_dir, self.log_dir):
            path.mkdir(parents=True, exist_ok=True)
