from __future__ import annotations

import logging
from logging.handlers import TimedRotatingFileHandler
import time

from .settings import Settings
from .transaction import TransactionManager


def run() -> None:
    settings = Settings.from_env()
    settings.ensure_dirs()
    handler = TimedRotatingFileHandler(settings.log_dir / "watchdog-error.log", when="midnight", backupCount=settings.log_retention_days, encoding="utf-8") if settings.log_retention_days else logging.NullHandler()
    logging.basicConfig(level=logging.ERROR, format="%(asctime)s %(levelname)s %(message)s", handlers=[handler])
    manager = TransactionManager(settings)
    while True:
        try:
            now = time.time()
            pending = manager.pending()
            if pending and now >= pending.deadline_epoch:
                logging.error("transaction %s expired; rolling back", pending.id)
                manager.rollback(pending.id)
        except Exception:
            logging.exception("rollback watchdog iteration failed")
        time.sleep(1)


if __name__ == "__main__":
    run()

