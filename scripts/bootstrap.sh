#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${XRER_REPO_URL:-https://github.com/asd5889921/xray-egress-router.git}"
BRANCH="${XRER_BRANCH:-main}"
APP_DIR="${XRER_APP_DIR:-/opt/xray-egress-router}"
CONFIG_DIR="${XRER_CONFIG_DIR:-/etc/xray-egress-router}"
RUN_DIR="${XRER_RUN_DIR:-/run/xray-egress-router}"
L2TP_INSTALLER_URL="${XRER_L2TP_INSTALLER_URL:-https://raw.githubusercontent.com/asd5889921/l2tp-vpn-installer/main/bootstrap.sh}"
UNINSTALL_URL="${XRER_UNINSTALL_URL:-https://raw.githubusercontent.com/asd5889921/xray-egress-router/main/scripts/uninstall.sh}"

[[ "$(id -u)" == 0 ]] || { echo "请使用 root 用户运行。" >&2; exit 1; }
command -v apt-get >/dev/null || { echo "仅支持 Debian/Ubuntu。" >&2; exit 1; }
[[ -r /dev/tty && -w /dev/tty ]] || { echo "需要交互式终端。" >&2; exit 1; }

if [[ -d /opt/l2tp-egress-router || -f /etc/systemd/system/l2er-web.service ]]; then
  echo "检测到原 l2tp-egress-router。两个项目不能在同一 VPS 上共用端口和 Xray。" >&2
  echo "为保护现有稳定服务，本安装已停止；请在另一台 VPS 安装 xray-egress-router。" >&2
  exit 1
fi

EXISTING=0
if [[ -e /etc/xl2tpd/xl2tpd.conf || -e /etc/ppp/options.xl2tpd || -e /etc/ppp/chap-secrets || -d "$APP_DIR" || -f /etc/systemd/system/xrer-web.service ]]; then
  EXISTING=1
  echo "检测到已有 L2TP 或 xray-egress-router 安装。"
  echo "1) 卸载  2) 安装/更新并保留现有 LNS  3) 取消"
  read -r -p "请选择 [1/2/3]: " ACTION </dev/tty
  if [[ "$ACTION" == "1" ]]; then
    read -r -p "卸载需要输入 REMOVE： " CONFIRM </dev/tty
    [[ "$CONFIRM" == "REMOVE" ]] || { echo "已取消。"; exit 1; }
    read -r -p "同时删除 xl2tpd/ppp？输入 PURGE 才删除，否则仅卸载本项目： " PURGE </dev/tty
    if [[ "$PURGE" == "PURGE" ]]; then curl -fsSL "$UNINSTALL_URL" | bash -s -- --purge-l2tp; else curl -fsSL "$UNINSTALL_URL" | bash; fi
    exit 0
  fi
  [[ "$ACTION" == "2" ]] || { echo "已取消。"; exit 1; }
fi

if [[ -f "$CONFIG_DIR/auth.json" ]]; then
  ADMIN_USER="$(XRER_CONFIG_DIR="$CONFIG_DIR" python3 -c 'import json, os; print(json.load(open(os.path.join(os.environ["XRER_CONFIG_DIR"], "auth.json")))["username"])' 2>/dev/null || echo admin)"
  ADMIN_PASS="$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')"; ADMIN_PASSWORD_GENERATED=1; ADMIN_PASSWORD_OUTPUT="$ADMIN_PASS"
else
read -r -p "Web 管理员用户名 [admin]: " ADMIN_USER </dev/tty
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD_GENERATED=0
while true; do
  read -r -s -p "Web 管理员密码（直接回车自动生成强密码）: " ADMIN_PASS </dev/tty
  echo >/dev/tty
  if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')"
    ADMIN_PASSWORD_GENERATED=1
    echo "已自动生成管理密码。"
    break
  fi
  read -r -s -p "再次输入管理密码: " ADMIN_PASS_CONFIRM </dev/tty
  echo >/dev/tty
  if [[ ${#ADMIN_PASS} -lt 12 ]]; then echo "密码至少需要 12 位。" >&2; continue; fi
  if [[ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]]; then echo "两次密码不一致。" >&2; continue; fi
  break
done
ADMIN_PASSWORD_OUTPUT="$ADMIN_PASS"
fi

if (( EXISTING == 0 )) && [[ -e /etc/xl2tpd/xl2tpd.conf || -e /etc/ppp/options.xl2tpd || -e /etc/ppp/chap-secrets ]]; then
  echo "检测到已有 L2TP/LNS 配置。为避免覆盖现有服务，本脚本停止。" >&2
  echo "请在全新 VPS 执行，或先手动备份并处理已有配置。" >&2
  exit 1
fi

echo "第一步：配置新 VPS 的纯 L2TP 服务端。"
echo "下面会让你填写 Panabit 将要使用的账号、密码、LNS 地址、地址池、MTU 和 DNS。"
if (( EXISTING == 0 )); then curl -fsSL "$L2TP_INSTALLER_URL" | bash; fi

L2TP_USER="$(awk 'NF >= 4 {gsub(/^"|"$/, "", $1); print $1; exit}' /etc/ppp/chap-secrets)"
L2TP_PASS="$(awk 'NF >= 4 {gsub(/^"|"$/, "", $3); print $3; exit}' /etc/ppp/chap-secrets)"
LNS_LOCAL_IP="$(awk -F= '/^[[:space:]]*local ip[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/xl2tpd/xl2tpd.conf)"
LNS_POOL="$(awk -F= '/^[[:space:]]*ip range[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/xl2tpd/xl2tpd.conf)"
L2TP_MTU="$(awk '/^[[:space:]]*mtu[[:space:]]+/{print $2; exit}' /etc/ppp/options.xl2tpd)"
L2TP_DNS="$(awk '/^[[:space:]]*ms-dns[[:space:]]+/{if (value) value=value ", "; value=value $2} END{print value}' /etc/ppp/options.xl2tpd)"

echo "第二步：安装 xray-egress-router。"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv python3-pip iproute2 iptables curl
if [[ -d "$APP_DIR/.git" ]]; then
  git -C "$APP_DIR" fetch origin "$BRANCH"
  git -C "$APP_DIR" reset --hard "origin/$BRANCH"
else
  git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$APP_DIR"
fi
python3 -m venv "$APP_DIR/.venv"
# The venv is reused during updates.  Without --upgrade/--force-reinstall,
# pip may keep an already-installed package with the same project version,
# leaving newly added API routes out of the running service.
"$APP_DIR/.venv/bin/pip" install --no-cache-dir --upgrade --force-reinstall "$APP_DIR"
"$APP_DIR/.venv/bin/python" -c 'from l2tp_multi_egress.xray_release import download_and_install; print(download_and_install())'

install -d -m 700 "$CONFIG_DIR" "$RUN_DIR"
install -d -m 755 /etc/ppp/ip-up.d /etc/ppp/ip-down.d
install -m 755 "$APP_DIR/config/ppp-hooks/90-xray-egress-router-up" /etc/ppp/ip-up.d/90-xray-egress-router
install -m 755 "$APP_DIR/config/ppp-hooks/90-xray-egress-router-down" /etc/ppp/ip-down.d/90-xray-egress-router

export XRER_CONFIG_DIR="$CONFIG_DIR" XRER_RUN_DIR="$RUN_DIR" XRER_XRAY_BINARY=/usr/local/bin/xray XRER_DRY_RUN=1
"$APP_DIR/.venv/bin/python" - <<'PY'
from l2tp_multi_egress.models import AppState
from l2tp_multi_egress.settings import Settings
from l2tp_multi_egress.storage import StateStore, atomic_write
from l2tp_multi_egress.xray import XrayManager
s = Settings.from_env()
s.ensure_dirs()
if s.state_file.exists():
    state = StateStore(s).load()
else:
    state = AppState()
    atomic_write(s.state_file, state.model_dump_json(indent=2) + "\n")
XrayManager(s).write_config(state)
PY
ADMIN_USER="$ADMIN_USER" ADMIN_PASS="$ADMIN_PASS" "$APP_DIR/.venv/bin/python" - <<'PY'
import os
from l2tp_multi_egress.auth import AuthManager
from l2tp_multi_egress.settings import Settings
auth = AuthManager(Settings.from_env())
if auth.initialized():
    auth.path.unlink()
    auth.secret_path.unlink(missing_ok=True)
    auth = AuthManager(Settings.from_env())
auth.initialize(os.environ["ADMIN_USER"], os.environ["ADMIN_PASS"])
PY
unset ADMIN_PASS ADMIN_PASS_CONFIRM

cat > /etc/systemd/system/xrer-xray.service <<EOF
[Unit]
Description=xray-egress-router Xray core
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/xray run -config $CONFIG_DIR/xray_config/config.json
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/xrer-web.service <<EOF
[Unit]
Description=xray-egress-router Web
After=xrer-xray.service xl2tpd.service
Requires=xrer-xray.service
[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=XRER_CONFIG_DIR=$CONFIG_DIR
Environment=XRER_RUN_DIR=$RUN_DIR
Environment=XRER_XRAY_BINARY=/usr/local/bin/xray
Environment=XRER_LISTEN_HOST=0.0.0.0
Environment=XRER_LISTEN_PORT=17890
ExecStart=$APP_DIR/.venv/bin/xrer-web
Restart=on-failure
RestartSec=3
User=root
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/xrer-watchdog.service <<EOF
[Unit]
Description=xray-egress-router rollback watchdog
After=network-online.target
[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=XRER_CONFIG_DIR=$CONFIG_DIR
Environment=XRER_RUN_DIR=$RUN_DIR
Environment=XRER_XRAY_BINARY=/usr/local/bin/xray
ExecStart=$APP_DIR/.venv/bin/xrer-watchdog
Restart=always
RestartSec=2
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xrer-xray xrer-watchdog xrer-web
# --now does not restart an already-running unit.  Updates must restart the
# processes so they load the freshly installed Python package and static UI.
systemctl restart xrer-xray xrer-watchdog xrer-web
SERVER_IP="$(curl --connect-timeout 5 -fsS https://api.ipify.org 2>/dev/null || true)"
[[ -n "$SERVER_IP" ]] || SERVER_IP="$(hostname -I | awk '{print $1}')"
SUMMARY_FILE=/root/xrer-install-summary.txt
umask 077
{
  echo
  echo "========== Xray Egress Router 安装信息 =========="
  printf '服务器地址：       %s\n' "$SERVER_IP"
  printf '服务器端口：       UDP 1701\n'
  printf 'VPN 账号：         %s\n' "$L2TP_USER"
  printf 'VPN 密码：         %s\n' "$L2TP_PASS"
  printf 'LNS 本地地址：     %s\n' "$LNS_LOCAL_IP"
  printf '客户端地址池：     %s\n' "$LNS_POOL"
  printf 'MTU：              %s\n' "$L2TP_MTU"
  printf 'DNS：              %s\n' "$L2TP_DNS"
  printf 'Web 地址：         http://%s:17890/\n' "$SERVER_IP"
  printf 'Web 管理员：       %s\n' "$ADMIN_USER"
  if [[ -n "$ADMIN_PASSWORD_OUTPUT" ]]; then
    printf 'Web 管理密码：     %s\n' "$ADMIN_PASSWORD_OUTPUT"
  else
    echo "Web 管理密码：     已存在，安装更新时无法读取明文"
  fi
  echo "信息保存位置：     $SUMMARY_FILE"
  echo "================================================"
} | tee "$SUMMARY_FILE"
chmod 600 "$SUMMARY_FILE"
