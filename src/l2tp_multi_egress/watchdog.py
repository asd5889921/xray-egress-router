from __future__ import annotations

import logging
from logging.handlers import TimedRotatingFileHandler
import time

from .network import NetworkManager
from .settings import Settings
from .storage import StateStore, exclusive_lock
from .transaction import TransactionManager


RECONCILE_INTERVAL_SECONDS = 30


def reconcile_network(settings: Settings) -> None:
    with exclusive_lock(settings.lock_file):
        NetworkManager(settings).apply(StateStore(settings).load())


def run() -> None:
    settings = Settings.from_env()
    settings.ensure_dirs()
    handler = TimedRotatingFileHandler(settings.log_dir / "watchdog-error.log", when="midnight", backupCount=settings.log_retention_days, encoding="utf-8") if settings.log_retention_days else logging.NullHandler()
    logging.basicConfig(level=logging.ERROR, format="%(asctime)s %(levelname)s %(message)s", handlers=[handler])
    manager = TransactionManager(settings)
    last_reconcile = 0.0
    while True:
        try:
            now = time.time()
            pending = manager.pending()
            if pending and now >= pending.deadline_epoch:
                logging.error("transaction %s expired; rolling back", pending.id)
                manager.rollback(pending.id)
            monotonic_now = time.monotonic()
            if monotonic_now - last_reconcile >= RECONCILE_INTERVAL_SECONDS:
                last_reconcile = monotonic_now
                reconcile_network(settings)
        except Exception:
            logging.exception("rollback watchdog iteration failed")
        time.sleep(1)


if __name__ == "__main__":
    run()

