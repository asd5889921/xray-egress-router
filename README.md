# xray-egress-router

IPv4 source-based egress routing for Panabit L2TP ingress traffic. The router
keeps the pure-L2TP server as the ingress and sends selected LAN source CIDRs
through Xray TPROXY outbounds.

## Scope

- Xray outbounds only: Shadowsocks, SOCKS5, and HTTP.
- No outbound L2TP client, network namespace, PPP egress, or L2TP policy table.
- Existing Panabit-facing `xl2tpd` remains the ingress and is not reused as an
  outbound client.
- TCP and UDP IPv4 TPROXY with automatic port and fwmark allocation.
- PPP reconnect hooks restore source-network return routes automatically.
- Web configuration, connectivity tests, transactional rollback, import/export,
  service status, and log retention controls.
- IPv6 is not forwarded by this routing layer.

## Install

On a new Debian/Ubuntu VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/asd5889921/xray-egress-router/main/scripts/bootstrap.sh | bash
```

The installer can create the pure-L2TP server used by Panabit, then installs the
Xray routing layer under isolated project paths:

- Application: `/opt/xray-egress-router`
- Configuration: `/etc/xray-egress-router`
- Runtime state: `/run/xray-egress-router`
- Services: `xrer-xray`, `xrer-web`, `xrer-watchdog`

The L2TP server is only an ingress. Add source LAN CIDRs and Xray outbounds from
the Web panel after installation.

## Development

```bash
git clone https://github.com/asd5889921/xray-egress-router.git
cd xray-egress-router
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

This repository was split from `l2tp-egress-router` so removing outbound L2TP
does not alter the stable original project.
