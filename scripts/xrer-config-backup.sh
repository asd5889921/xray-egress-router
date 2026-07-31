#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${XRER_CONFIG_DIR:-/etc/xray-egress-router}"
STATE_FILE="$CONFIG_DIR/state.json"
BACKUP_DIR="${XRER_BACKUP_DIR:-/var/backups/xray-egress-router}"
PYTHON_BIN="${XRER_PYTHON:-/opt/xray-egress-router/.venv/bin/python3}"
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN="python3"

usage() { echo "Usage: $0 backup <file.tar.gz> | restore <file.tar.gz>"; exit 2; }
[[ $# -eq 2 ]] || usage
command="$1"
archive="$2"

case "$command" in
  backup)
    [[ -f "$STATE_FILE" ]] || { echo "state file not found: $STATE_FILE" >&2; exit 1; }
    install -d -m 700 "$(dirname "$archive")"
    tar --create --gzip --file "$archive" --directory "$CONFIG_DIR" state.json
    chmod 600 "$archive"
    echo "Configuration backup written to $archive"
    ;;
  restore)
    [[ -f "$archive" ]] || { echo "backup file not found: $archive" >&2; exit 1; }
    temporary="$(mktemp -d)"
    trap 'rm -rf "$temporary"' EXIT
    tar --extract --gzip --file "$archive" --directory "$temporary"
    [[ -f "$temporary/state.json" ]] || { echo "backup does not contain state.json" >&2; exit 1; }
    "$PYTHON_BIN" - "$temporary/state.json" <<'PY'
import json, sys
from pydantic import ValidationError
from l2tp_multi_egress.models import AppState
data = json.load(open(sys.argv[1], encoding="utf-8"))
try:
    AppState.model_validate(data)
except ValidationError as exc:
    raise SystemExit(f"invalid xrer state: {exc}")
PY
    install -d -m 700 "$BACKUP_DIR"
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    [[ -f "$STATE_FILE" ]] && cp -p "$STATE_FILE" "$BACKUP_DIR/state-before-restore-$timestamp.json"
    install -m 600 "$temporary/state.json" "$STATE_FILE"
    systemctl restart xrer-web xrer-watchdog
    echo "Configuration restored. Existing admin credentials were preserved."
    ;;
  *) usage ;;
esac
