from __future__ import annotations

import json
import time
import uuid

from .models import AppState, Transaction, utcnow
from .network import NetworkManager
from .settings import Settings
from .storage import StateStore, atomic_write, exclusive_lock
from .xray import XrayManager


class TransactionManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = StateStore(settings)
        self.xray = XrayManager(settings)
        self.network = NetworkManager(settings)

    def pending(self) -> Transaction | None:
        if not self.settings.pending_file.exists():
            return None
        return Transaction.model_validate_json(self.settings.pending_file.read_text(encoding="utf-8"))

    def apply(self, candidate: AppState) -> Transaction:
        with exclusive_lock(self.settings.lock_file):
            if self.pending():
                raise RuntimeError("已有待确认变更，请先确认或回滚")
            previous = self.store.load()
            candidate = candidate.model_copy(update={"revision": previous.revision + 1, "updated_at": utcnow()})
            candidate = AppState.model_validate(candidate.model_dump())
            self.xray.require_version()
            candidate_path = self.xray.write_config(candidate, "candidate.json")
            self.xray.validate(candidate_path)
            snapshot = self.store.snapshot(previous, "pre-change")
            transaction = Transaction(
                id=uuid.uuid4().hex,
                deadline_epoch=time.time() + self.settings.rollback_seconds,
                previous_snapshot=snapshot.name,
                candidate_revision=candidate.revision,
            )
            atomic_write(self.settings.pending_file, transaction.model_dump_json(indent=2) + "\n")
            try:
                if previous.fake_dns != candidate.fake_dns:
                    self.xray.restart_with(candidate)
                else:
                    self.xray.apply_dynamic(previous, candidate)
                self.network.apply(candidate)
                self.store.save(candidate)
                self.xray.write_config(candidate)
            except Exception:
                try:
                    if previous.fake_dns != candidate.fake_dns:
                        self.xray.restart_with(previous)
                    else:
                        self.xray.apply_dynamic(candidate, previous)
                    self.network.apply(previous)
                    self.store.save(previous)
                    self.xray.write_config(previous)
                finally:
                    self.settings.pending_file.unlink(missing_ok=True)
                raise
            return transaction

    def confirm(self, transaction_id: str) -> None:
        with exclusive_lock(self.settings.lock_file):
            transaction = self.pending()
            if not transaction or transaction.id != transaction_id:
                raise ValueError("待确认事务不存在或 ID 不匹配")
            self.settings.pending_file.unlink(missing_ok=True)

    def rollback(self, transaction_id: str | None = None) -> AppState:
        with exclusive_lock(self.settings.lock_file):
            transaction = self.pending()
            if not transaction:
                raise ValueError("没有待回滚事务")
            if transaction_id and transaction.id != transaction_id:
                raise ValueError("事务 ID 不匹配")
            current = self.store.load()
            previous = self.store.load_snapshot(transaction.previous_snapshot)
            if current.fake_dns != previous.fake_dns:
                self.xray.restart_with(previous)
            else:
                self.xray.apply_dynamic(current, previous)
            self.network.apply(previous)
            self.store.save(previous)
            self.xray.write_config(previous)
            self.settings.pending_file.unlink(missing_ok=True)
            return previous

    def apply_history(self, name: str) -> Transaction:
        return self.apply(self.store.load_snapshot(name))
