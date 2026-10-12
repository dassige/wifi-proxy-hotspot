#!/bin/bash
# ==============================================================================
# Wi-Fi Proxy Hotspot — installer
# ==============================================================================
# Turns a Debian 12+/Raspberry Pi OS box (NetworkManager + netplan or plain
# NetworkManager) into a Wi-Fi hotspot that transparently proxies every
# connected device's TCP traffic through an upstream HTTP or SOCKS5 proxy,
# except an internal network range you choose, or specific domains you list
# via routing rules (exact/wildcard/regex, each routed to the proxy or
# direct) — plus a small PAM-authenticated web panel (Linux login required)
# to manage all of the above afterwards, without touching the command line
# again.
#
# Run as root on the target machine itself (not over a connection that will
# be reconfigured, if you can help it — see the warning before Step 1 below).
#
# See ../Wi-Fi-Proxy-Hotspot-Guide.pdf for full background, architecture and
# troubleshooting. This script automates the "Admin — Installation" section
# of that guide exactly.
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root (sudo ./install.sh)." >&2
    exit 1
fi

if ! command -v nmcli >/dev/null 2>&1; then
    echo "nmcli (NetworkManager) not found. This installer targets Debian 12+" >&2
    echo "/ Raspberry Pi OS Bookworm-or-later images that use NetworkManager." >&2
    exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get not found. This installer targets Debian-based systems." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AP_CONN_NAME="Gateway-AP"

# The admin panel's Help page reports the running version, so read it fresh
# from pyproject.toml here — the actual source of truth — rather than from
# some copy that could go stale. This is what "enforces" the sync: there is no intermediate file
# to forget to regenerate. Deploy pyproject.toml alongside this package/
# folder, one directory up, preserving its normal position in the repo (e.g.
# copy the whole repository rather than package/ on its own) for this to work.
PYPROJECT_PATH="$SCRIPT_DIR/../pyproject.toml"
if [ ! -f "$PYPROJECT_PATH" ]; then
    echo "pyproject.toml not found at $PYPROJECT_PATH." >&2
    echo "Copy it alongside this package/ folder (one directory above it) before" >&2
    echo "installing — e.g. copy the whole repository rather than just package/ on its own." >&2
    exit 1
fi
APP_VERSION="$(grep -m1 -E '^version = ' "$PYPROJECT_PATH" | sed -E 's/^version = "(.*)"$/\1/')" || true
APP_VERSION_DATE="$(grep -m1 -E '^versionDate = ' "$PYPROJECT_PATH" | sed -E 's/^versionDate = "(.*)"$/\1/')" || true
if [ -z "$APP_VERSION" ] || [ -z "$APP_VERSION_DATE" ]; then
    echo "Could not parse version/versionDate out of $PYPROJECT_PATH — check its" >&2
    echo "[project] version and [tool.dgs-autoversion] versionDate entries." >&2
    exit 1
fi
echo "Wi-Fi Proxy Hotspot v$APP_VERSION (built $APP_VERSION_DATE)"
echo

ask() {
    # ask "Prompt" "default" -> echoes the answer
    local prompt="$1" default="${2:-}" reply
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " reply
        echo "${reply:-$default}"
    else
        read -r -p "$prompt: " reply
        echo "$reply"
    fi
}

ask_secret() {
    local prompt="$1" reply
    read -r -s -p "$prompt: " reply
    echo >&2
    echo "$reply"
}

echo "== Wi-Fi Proxy Hotspot installer =="
echo

# ------------------------------------------------------------------------
# Step 0 — gather configuration
# ------------------------------------------------------------------------
LAN_IFACE=$(ask "Wired interface used to reach the internet/internal network" "eth0")
LAN_IP=$(ask "Static IP for $LAN_IFACE (CIDR, e.g. 192.168.1.10/24)")
LAN_GATEWAY=$(ask "Default gateway (e.g. 192.168.1.1)")
LAN_DNS=$(ask "DNS servers (space-separated)" "$LAN_GATEWAY 1.1.1.1")

AP_IFACE=$(ask "Wireless interface to broadcast the hotspot on" "wlan0")
AP_SSID=$(ask "Hotspot SSID")
AP_PASSPHRASE=$(ask_secret "Hotspot passphrase (blank = auto-generate one)")
if [ -z "$AP_PASSPHRASE" ]; then
    AP_PASSPHRASE=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 || true)
    echo "Generated hotspot passphrase: $AP_PASSPHRASE"
fi
AP_SUBNET=$(ask "Hotspot's own subnet (CIDR, gateway address on the AP side)" "192.168.4.1/24")

LAN_IP_ONLY="${LAN_IP%%/*}"
LAN_MASK="${LAN_IP##*/}"
LAN_NETWORK="${LAN_IP_ONLY%.*}.0"
BYPASS_CIDR=$(ask "Internal network range that should bypass the proxy (CIDR)" "$LAN_NETWORK/$LAN_MASK")

PROXY_TYPE=$(ask "Upstream proxy type (http-connect or socks5)" "http-connect")
PROXY_IP=$(ask "Upstream proxy address")
PROXY_PORT=$(ask "Upstream proxy port")
PROXY_LOGIN=$(ask "Upstream proxy username (blank if none)")
PROXY_PASSWORD=$(ask_secret "Upstream proxy password (blank if none)")

ADMIN_USERS=$(ask "Linux username(s) allowed to log into the admin web panel (comma-separated)" "$(logname 2>/dev/null || echo admin)")
WEBADMIN_IP="${LAN_IP%%/*}"
WEBADMIN_PORT=$(ask "Admin web panel port" "8443")

echo
echo "Everything above will now be applied. Passwords are written only to"
echo "files on this machine, never echoed again or logged."
read -r -p "Press Enter to continue, Ctrl+C to abort... "

# ------------------------------------------------------------------------
# Step 1 — static IP on the wired interface
# ------------------------------------------------------------------------
echo "== Step 1: static IP on $LAN_IFACE =="
LAN_CONN=$(nmcli -t -f GENERAL.CONNECTION device show "$LAN_IFACE" | cut -d: -f2)
if [ -z "$LAN_CONN" ] || [ "$LAN_CONN" = "--" ]; then
    echo "No active NetworkManager connection found on $LAN_IFACE." >&2
    echo "Connect $LAN_IFACE first (even via DHCP), then re-run this script." >&2
    exit 1
fi
echo "NOTE: if you are connected over SSH via $LAN_IFACE, this step changes"
echo "its address and your session will drop. Reconnect on $WEBADMIN_IP afterwards."
nmcli connection modify "$LAN_CONN" \
    ipv4.method manual \
    ipv4.addresses "$LAN_IP" \
    ipv4.gateway "$LAN_GATEWAY" \
    ipv4.dns "$LAN_DNS"
nmcli connection up "$LAN_CONN" || true

# ------------------------------------------------------------------------
# Step 2 — packages
# ------------------------------------------------------------------------
echo "== Step 2: installing packages =="
echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    redsocks iptables-persistent python3-flask python3-pam gunicorn iw \
    python3-dnspython ipset python3-qrcode dnsmasq-base openssl

# ------------------------------------------------------------------------
# Step 3 — Wi-Fi access point (NetworkManager shared connection)
# ------------------------------------------------------------------------
echo "== Step 3: creating the Wi-Fi access point =="
nmcli connection delete "$AP_CONN_NAME" >/dev/null 2>&1 || true
nmcli connection add type wifi ifname "$AP_IFACE" con-name "$AP_CONN_NAME" \
    autoconnect yes ssid "$AP_SSID"
nmcli connection modify "$AP_CONN_NAME" 802-11-wireless.mode ap 802-11-wireless.band bg
nmcli connection modify "$AP_CONN_NAME" wifi-sec.key-mgmt wpa-psk
nmcli connection modify "$AP_CONN_NAME" wifi-sec.psk "$AP_PASSPHRASE"
nmcli connection modify "$AP_CONN_NAME" ipv4.method shared ipv4.addresses "$AP_SUBNET"

# Route the hotspot's own DNS resolution through our pattern-router daemon
# (deployed in Step 7) rather than straight upstream, so URL-pattern rules
# added later via the admin panel can take effect without touching this file
# again. max-ttl caps the TTL handed to clients (dnsmasq still caches the
# real one) so devices re-ask within a minute; together with the cache flush
# the firewall-rebuild helper does on every rule change, a new or edited
# rule reaches already-connected devices within about a minute.
mkdir -p /etc/NetworkManager/dnsmasq-shared.d
cat > /etc/NetworkManager/dnsmasq-shared.d/pattern-routing.conf <<'EOF'
server=127.0.0.1#15353
# Clients re-resolve within 60s, so pattern-rule changes reach them quickly.
max-ttl=60
EOF

nmcli connection up "$AP_CONN_NAME"

# ------------------------------------------------------------------------
# Step 4 — redsocks (transparent proxy)
# ------------------------------------------------------------------------
echo "== Step 4: configuring redsocks =="
cat > /etc/redsocks.conf <<EOF
base {
    log_debug = off;
    log_info = on;
    log = "syslog:daemon";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 0.0.0.0;
    local_port = 20000;
    ip = $PROXY_IP;
    port = $PROXY_PORT;
    type = $PROXY_TYPE;
    login = "$PROXY_LOGIN";
    password = "$PROXY_PASSWORD";
}
EOF
chown root:redsocks /etc/redsocks.conf
chmod 660 /etc/redsocks.conf
# The vendor unit only waits for network.target and never retries. A proxy
# profile given by hostname then fails to resolve at boot and redsocks stays
# dead (real incident 2026-09-30: 4.5 hours unproxied). The drop-in waits for
# network-online, restarts on failure, and re-runs the firewall init if it
# failed because of it. The file itself explains each line.
mkdir -p /etc/systemd/system/redsocks.service.d
install -m 644 -o root -g root "$SCRIPT_DIR/redsocks-override.conf" /etc/systemd/system/redsocks.service.d/override.conf
systemctl daemon-reload
systemctl enable --now redsocks
systemctl restart redsocks

# ------------------------------------------------------------------------
# Step 4b — redsocks performance patches (optional, non-fatal)
# ------------------------------------------------------------------------
# Stock redsocks 0.5 has two real perf bugs found investigating slow
# proxied connections over a long-distance link to the proxy: it waits for a 407 challenge before sending Proxy-Authorization instead of
# sending it proactively, and it never sets TCP_NODELAY on the relay
# sockets. Both cost real round trips on a high-latency link to the
# upstream proxy. Patches live in redsocks-patches/ next to this script.
# This whole step is best-effort: no internet access to Debian's source
# mirrors, or any build failure, leaves the stock binary in place rather
# than failing the install, since this is a performance optimization, not
# a functional requirement -- see redsocks-patches/README.md to apply it
# manually later.
echo "== Step 4b: applying redsocks performance patches (optional) =="
apply_redsocks_patches() {
    set -e
    command -v gcc >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential dpkg-dev
    dpkg -s libevent-dev >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y libevent-dev

    local added_deb_src=""
    if ! apt-get source --print-uris redsocks >/dev/null 2>&1; then
        # Debian's own source mirror, for whichever release this box runs
        # (Raspberry Pi OS is built on the same Debian release).
        local codename keyring
        codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
        [ -n "$codename" ] || return 1
        keyring=/usr/share/keyrings/debian-archive-keyring.pgp
        [ -f "$keyring" ] || keyring=/usr/share/keyrings/debian-archive-keyring.gpg
        printf 'Types: deb-src\nURIs: http://deb.debian.org/debian/\nSuites: %s %s-updates\nComponents: main contrib non-free non-free-firmware\nSigned-By: %s\n' \
            "$codename" "$codename" "$keyring" \
            > /etc/apt/sources.list.d/rasp-proxy-temp-deb-src.sources
        added_deb_src=1
        apt-get update
    fi

    local build_dir
    build_dir="$(mktemp -d)"
    (
        cd "$build_dir"
        apt-get source redsocks
        cd redsocks-*/
        patch -p1 < "$SCRIPT_DIR/redsocks-patches/0001-tcp-nodelay.patch"
        patch -p1 < "$SCRIPT_DIR/redsocks-patches/0002-preemptive-basic-auth.patch"
        make
        backup="/usr/sbin/redsocks.orig-$(dpkg-query -W -f='${Version}' redsocks)"
        [ -f "$backup" ] || cp /usr/sbin/redsocks "$backup"
        install -m 755 -o root -g root redsocks /usr/sbin/redsocks
    )
    rm -rf "$build_dir"

    if [ -n "$added_deb_src" ]; then
        rm -f /etc/apt/sources.list.d/rasp-proxy-temp-deb-src.sources
        apt-get update
    fi
    systemctl restart redsocks
}
if (apply_redsocks_patches); then
    echo "  redsocks patches applied successfully."
else
    echo "  WARNING: could not build/apply redsocks performance patches -- continuing with the stock redsocks binary. See redsocks-patches/README.md to apply manually later." >&2
fi

# ------------------------------------------------------------------------
# Step 5 — firewall: redirect AP traffic into redsocks, except BYPASS_CIDR
# ------------------------------------------------------------------------
echo "== Step 5: firewall rules =="
iptables -t nat -N REDSOCKS 2>/dev/null || iptables -t nat -F REDSOCKS
iptables -t nat -A REDSOCKS -d "$BYPASS_CIDR" -j RETURN
iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 20000
if ! iptables -t nat -C PREROUTING -i "$AP_IFACE" -p tcp -j REDSOCKS 2>/dev/null; then
    iptables -t nat -A PREROUTING -i "$AP_IFACE" -p tcp -j REDSOCKS
fi
netfilter-persistent save

# ------------------------------------------------------------------------
# Step 6 — dedicated service account for the admin web app
# ------------------------------------------------------------------------
echo "== Step 6: service accounts =="
if ! id proxyadmin-svc >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid redsocks proxyadmin-svc
fi
if ! id rasp-proxy-dns >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid redsocks rasp-proxy-dns
fi

# ------------------------------------------------------------------------
# Step 7 — deploy the admin web app and its root-owned helpers
# ------------------------------------------------------------------------
echo "== Step 7: deploying the admin web app =="
mkdir -p /opt/rasp-proxy-admin
install -m 640 -o root -g redsocks "$SCRIPT_DIR/app.py" /opt/rasp-proxy-admin/app.py
install -m 640 -o root -g redsocks "$SCRIPT_DIR/dns_router.py" /opt/rasp-proxy-admin/dns_router.py
install -m 640 -o root -g redsocks "$SCRIPT_DIR/pattern_match.py" /opt/rasp-proxy-admin/pattern_match.py
install -m 640 -o root -g redsocks "$SCRIPT_DIR/proxy_check.py" /opt/rasp-proxy-admin/proxy_check.py
install -m 640 -o root -g redsocks "$SCRIPT_DIR/proxy_doh.py" /opt/rasp-proxy-admin/proxy_doh.py
install -m 640 -o root -g redsocks "$SCRIPT_DIR/mailer.py" /opt/rasp-proxy-admin/mailer.py
install -m 640 -o root -g redsocks "$SCRIPT_DIR/help_texts.py" /opt/rasp-proxy-admin/help_texts.py
# The panel's page templates (Jinja): the whole templates/ tree.
(cd "$SCRIPT_DIR" && find templates -type f) | while read -r f; do
    install -D -m 640 -o root -g redsocks "$SCRIPT_DIR/$f" "/opt/rasp-proxy-admin/$f"
done
chown -R root:redsocks /opt/rasp-proxy-admin/templates
find /opt/rasp-proxy-admin/templates -type d -exec chmod 750 {} +
# The admin/user guide PDF, so the panel's Help page works even with no
# internet access on this box. Optional: an older checkout of this package
# predating the Help page won't have it, so don't fail the install over it.
if [ -f "$SCRIPT_DIR/Wi-Fi-Proxy-Hotspot-Guide.pdf" ]; then
    install -m 640 -o root -g redsocks "$SCRIPT_DIR/Wi-Fi-Proxy-Hotspot-Guide.pdf" /opt/rasp-proxy-admin/Wi-Fi-Proxy-Hotspot-Guide.pdf
else
    echo "  (note: Wi-Fi-Proxy-Hotspot-Guide.pdf not found next to install.sh — the panel's Help page will 404 until it's deployed)"
fi
# What the Help page shows as the running version (app.py reads this first).
printf '{"version": "%s", "date": "%s"}\n' "$APP_VERSION" "$APP_VERSION_DATE" > /opt/rasp-proxy-admin/version.json
chown root:redsocks /opt/rasp-proxy-admin/version.json
chmod 640 /opt/rasp-proxy-admin/version.json
chown root:redsocks /opt/rasp-proxy-admin
chmod 750 /opt/rasp-proxy-admin

install -m 750 -o root -g root "$SCRIPT_DIR/rasp-proxy-pamcheck.py" /usr/local/sbin/rasp-proxy-pamcheck
install -m 750 -o root -g root "$SCRIPT_DIR/rasp-proxy-rebuild-firewall.py" /usr/local/sbin/rasp-proxy-rebuild-firewall
install -m 750 -o root -g root "$SCRIPT_DIR/rasp-proxy-traffic-sync.py" /usr/local/sbin/rasp-proxy-traffic-sync
install -m 750 -o root -g root "$SCRIPT_DIR/rasp-proxy-health.py" /usr/local/sbin/rasp-proxy-health
install -m 644 -o root -g root "$SCRIPT_DIR/pam-service" /etc/pam.d/rasp-proxy-admin

# Mutable state (the saved proxy-profile list) lives here rather than under
# /etc, and must be owned by the service account itself: /var/lib is not
# group-writable, so the unprivileged app could never create this directory
# on its own the first time it tries to save a profile.
mkdir -p /var/lib/rasp-proxy-admin
chown proxyadmin-svc:redsocks /var/lib/rasp-proxy-admin
chmod 750 /var/lib/rasp-proxy-admin
cat > /var/lib/rasp-proxy-admin/proxies.json <<EOF
{
  "next_port": 20001,
  "profiles": {
    "default": {
      "description": "Initial proxy configured at install time",
      "type": "$PROXY_TYPE",
      "ip": "$PROXY_IP",
      "port": "$PROXY_PORT",
      "login": "$PROXY_LOGIN",
      "password": "$PROXY_PASSWORD",
      "local_port": 20000
    }
  }
}
EOF
chown proxyadmin-svc:redsocks /var/lib/rasp-proxy-admin/proxies.json
chmod 660 /var/lib/rasp-proxy-admin/proxies.json

# routing rules, the global default action, and the internal bypass
# CIDR all live in one file: readable by both the admin app (owner) and the
# DNS router daemon (group redsocks), writable only by the app. bypass_cidr
# lives here (not derived by parsing live iptables output) specifically so
# the firewall can be rebuilt from scratch at boot even if ipsets — which
# are never persisted across a reboot — didn't survive it. Default action
# starts pointed at the one profile just created above, matching Step 5's
# bootstrap chain.
cat > /var/lib/rasp-proxy-admin/pattern_rules.json <<EOF
{
  "bypass_cidr": "$BYPASS_CIDR",
  "default_action": "default",
  "rules": []
}
EOF
chown proxyadmin-svc:redsocks /var/lib/rasp-proxy-admin/pattern_rules.json
chmod 640 /var/lib/rasp-proxy-admin/pattern_rules.json

# Re-derive the chain from the JSON stores just written, using the exact
# same helper (and code path) the admin panel uses for every later change
# — rather than trusting Step 5's hand-built version to stay in sync with
# it, which is exactly the kind of drift that has bitten this project before.
/usr/local/sbin/rasp-proxy-rebuild-firewall "$AP_IFACE"

mkdir -p /etc/rasp-proxy-admin/tls
if [ ! -f /etc/rasp-proxy-admin/tls/cert.pem ]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /etc/rasp-proxy-admin/tls/key.pem \
        -out /etc/rasp-proxy-admin/tls/cert.pem \
        -days 3650 -subj "/CN=wifi-proxy-hotspot.local"
fi
chown -R root:redsocks /etc/rasp-proxy-admin
chmod 750 /etc/rasp-proxy-admin /etc/rasp-proxy-admin/tls
chmod 640 /etc/rasp-proxy-admin/tls/key.pem /etc/rasp-proxy-admin/tls/cert.pem

# ------------------------------------------------------------------------
# Step 8 — sudoers: the exact, minimal set of root actions the web app needs
# ------------------------------------------------------------------------
echo "== Step 8: sudoers =="
SUDOERS_TMP=$(mktemp)
{
    IFS=',' read -ra USERS <<< "$ADMIN_USERS"
    for u in "${USERS[@]}"; do
        u="$(echo "$u" | xargs)"
        [ -n "$u" ] && echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/local/sbin/rasp-proxy-pamcheck $u"
    done
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/systemctl restart redsocks"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli connection modify $AP_CONN_NAME *"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli connection up $AP_CONN_NAME"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli connection down $AP_CONN_NAME"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /bin/cat /var/lib/NetworkManager/dnsmasq-$AP_IFACE.leases"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/local/sbin/rasp-proxy-rebuild-firewall *"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/sbin/iptables -t nat -L REDSOCKS -n"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/systemd-run --on-active=3 /usr/sbin/reboot"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/local/sbin/rasp-proxy-traffic-sync *"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/sbin/iptables -t mangle -L WPXACCT_UP -n -v -x"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/sbin/iptables -t mangle -L WPXACCT_DOWN -n -v -x"
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block rasp-proxy-health.service"
    # Read-only: the hotspot passphrase, for the Wi-Fi page's "Show join QR code" (never stored).
    echo "proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli -s -g 802-11-wireless-security.psk connection show $AP_CONN_NAME"
} > "$SUDOERS_TMP"
visudo -c -f "$SUDOERS_TMP"
install -m 440 -o root -g root "$SUDOERS_TMP" /etc/sudoers.d/proxyadmin-svc
rm -f "$SUDOERS_TMP"
visudo -c

# ------------------------------------------------------------------------
# Step 9 — systemd service for the admin web app
# ------------------------------------------------------------------------
echo "== Step 9: admin web app service =="
cat > /etc/systemd/system/rasp-proxy-admin.service <<EOF
[Unit]
Description=Wi-Fi Proxy Hotspot admin web panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=proxyadmin-svc
Group=redsocks
WorkingDirectory=/opt/rasp-proxy-admin
Environment=RASP_PROXY_ADMIN_USERS=$ADMIN_USERS
Environment=RASP_PROXY_AP_CONN=$AP_CONN_NAME
Environment=RASP_PROXY_AP_IFACE=$AP_IFACE
Environment=RASP_PROXY_VERSION=$APP_VERSION
Environment="RASP_PROXY_VERSION_DATE=$APP_VERSION_DATE"
ExecStart=/usr/bin/gunicorn --bind $WEBADMIN_IP:$WEBADMIN_PORT --certfile=/etc/rasp-proxy-admin/tls/cert.pem --keyfile=/etc/rasp-proxy-admin/tls/key.pem --workers 2 app:app
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now rasp-proxy-admin

# ------------------------------------------------------------------------
# Step 10 — DNS pattern-router daemon (backs the "Routing Rules" feature)
# ------------------------------------------------------------------------
echo "== Step 10: DNS pattern-router service =="
cat > /etc/systemd/system/rasp-proxy-dns-router.service <<EOF
[Unit]
Description=Wi-Fi Proxy Hotspot DNS pattern router
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rasp-proxy-dns
Group=redsocks
# CAP_NET_ADMIN: ipset tagging. CAP_NET_RAW: passive capture of hotspot
# devices' DNS queries for the admin panel's DNS Lookups page.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
Environment=RASP_PROXY_AP_IFACE=$AP_IFACE
# /run/rasp-proxy-dns (tmpfs): the lookups snapshot, group-readable by the
# admin app (both run with Group=redsocks), never written to disk.
RuntimeDirectory=rasp-proxy-dns
RuntimeDirectoryMode=0750
WorkingDirectory=/opt/rasp-proxy-admin
ExecStart=/usr/bin/python3 /opt/rasp-proxy-admin/dns_router.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now rasp-proxy-dns-router

# ------------------------------------------------------------------------
# Step 11 — boot-time firewall rebuild (ipsets are never persisted by
# netfilter-persistent; without this, a saved rule referencing a
# since-vanished ipset makes the *whole* saved ruleset fail to restore
# after every reboot, silently leaving hotspot traffic completely
# unfiltered)
# ------------------------------------------------------------------------
echo "== Step 11: boot-time firewall init service =="
cat > /etc/systemd/system/rasp-proxy-firewall-init.service <<EOF
[Unit]
Description=Wi-Fi Proxy Hotspot firewall init (rebuilds REDSOCKS chain + ipsets on boot)
After=network-online.target redsocks.service
Wants=network-online.target
Requires=redsocks.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rasp-proxy-rebuild-firewall $AP_IFACE
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now rasp-proxy-firewall-init

# ------------------------------------------------------------------------
# Step 12 — periodic health check + email alerts (backs the Overview page)
# ------------------------------------------------------------------------
# Runs as root: it reads the firewall chains and the kernel log. It only
# ever reports; it never changes routing. Alert emails are off until SMTP
# settings are saved on the System page.
echo "== Step 12: health check timer =="
cat > /etc/systemd/system/rasp-proxy-health.service <<EOF
[Unit]
Description=Wi-Fi Proxy Hotspot health check (Overview page + email alerts)
After=network-online.target

[Service]
Type=oneshot
Environment=RASP_PROXY_AP_IFACE=$AP_IFACE
Environment=RASP_PROXY_AP_CONN=$AP_CONN_NAME
Environment=RASP_PROXY_PANEL_URL=https://$WEBADMIN_IP:$WEBADMIN_PORT/
ExecStart=/usr/local/sbin/rasp-proxy-health
TimeoutStartSec=120
Nice=10
EOF
cat > /etc/systemd/system/rasp-proxy-health.timer <<EOF
[Unit]
Description=Run the Wi-Fi Proxy Hotspot health check every 2 minutes

[Timer]
OnBootSec=90s
OnUnitActiveSec=2min
AccuracySec=15s

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now rasp-proxy-health.timer

echo
echo "================================================================"
echo " Install complete."
echo " Hotspot SSID:      $AP_SSID"
echo " Hotspot passphrase: $AP_PASSPHRASE"
echo " Admin panel:       https://$WEBADMIN_IP:$WEBADMIN_PORT/"
echo " Admin panel login: your Linux account ($ADMIN_USERS)"
echo " routing rules: add them from the admin panel once logged in."
echo "================================================================"
