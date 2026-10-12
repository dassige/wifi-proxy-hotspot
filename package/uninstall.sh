#!/bin/bash
# ==============================================================================
# Wi-Fi Proxy Hotspot — uninstaller
# ==============================================================================
# Removes everything install.sh created: the admin web app, its service
# account, sudoers rule, systemd services (including the health-check
# timer), the redsocks transparent-proxy config and firewall chain, and the
# hotspot's NetworkManager connection.
#
# Does NOT touch: the static IP set on the wired interface (revert that
# manually via `nmcli connection modify <conn> ipv4.method auto` if wanted),
# or the redsocks/iptables-persistent/python3-flask/etc. packages themselves.
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root (sudo ./uninstall.sh)." >&2
    exit 1
fi

AP_CONN_NAME="Gateway-AP"

read -r -p "This removes the Wi-Fi Proxy Hotspot admin panel, redsocks config, "\
"firewall rules and the $AP_CONN_NAME Wi-Fi connection. Continue? [y/N] " CONFIRM
if [ "${CONFIRM,,}" != "y" ]; then
    echo "Aborted."
    exit 0
fi

echo "== Stopping and removing the admin web app, DNS router and firewall-init services =="
systemctl disable --now rasp-proxy-admin 2>/dev/null || true
systemctl disable --now rasp-proxy-dns-router 2>/dev/null || true
systemctl disable --now rasp-proxy-firewall-init 2>/dev/null || true
systemctl disable --now rasp-proxy-health.timer 2>/dev/null || true
systemctl stop rasp-proxy-health.service 2>/dev/null || true
rm -f /etc/systemd/system/rasp-proxy-admin.service
rm -f /etc/systemd/system/rasp-proxy-dns-router.service
rm -f /etc/systemd/system/rasp-proxy-firewall-init.service
rm -f /etc/systemd/system/rasp-proxy-health.service /etc/systemd/system/rasp-proxy-health.timer
systemctl daemon-reload

echo "== Removing sudoers rule =="
rm -f /etc/sudoers.d/proxyadmin-svc

echo "== Removing service accounts =="
if id proxyadmin-svc >/dev/null 2>&1; then
    userdel proxyadmin-svc
fi
if id rasp-proxy-dns >/dev/null 2>&1; then
    userdel rasp-proxy-dns
fi

echo "== Removing admin web app files =="
rm -rf /opt/rasp-proxy-admin
rm -rf /etc/rasp-proxy-admin
rm -rf /var/lib/rasp-proxy-admin
rm -f /usr/local/sbin/rasp-proxy-pamcheck
rm -f /usr/local/sbin/rasp-proxy-rebuild-firewall
rm -f /usr/local/sbin/rasp-proxy-traffic-sync
rm -f /usr/local/sbin/rasp-proxy-health
rm -rf /run/rasp-proxy-health
rm -f /etc/pam.d/rasp-proxy-admin
rm -f /etc/NetworkManager/dnsmasq-shared.d/pattern-routing.conf

echo "== Removing firewall rules and pattern-rule ipsets =="
iptables -t nat -D PREROUTING -i wlan0 -p tcp -j REDSOCKS 2>/dev/null || true
iptables -t nat -F REDSOCKS 2>/dev/null || true
iptables -t nat -X REDSOCKS 2>/dev/null || true
# Leak guards (forced DNS, DNS-over-TLS block, IPv6 block).
iptables -t nat -D PREROUTING -i wlan0 -j WPXDNS 2>/dev/null || true
iptables -t nat -F WPXDNS 2>/dev/null || true
iptables -t nat -X WPXDNS 2>/dev/null || true
iptables -t filter -D FORWARD -i wlan0 -j WPXGUARD 2>/dev/null || true
iptables -t filter -F WPXGUARD 2>/dev/null || true
iptables -t filter -X WPXGUARD 2>/dev/null || true
ip6tables -t filter -D FORWARD -i wlan0 -j WPXGUARD6 2>/dev/null || true
ip6tables -t filter -F WPXGUARD6 2>/dev/null || true
ip6tables -t filter -X WPXGUARD6 2>/dev/null || true
# Before the ipsets: WPXQUIC references them, and a referenced ipset can't be destroyed.
iptables -t filter -D FORWARD -i wlan0 -p udp --dport 443 -j WPXQUIC 2>/dev/null || true
iptables -t filter -F WPXQUIC 2>/dev/null || true
iptables -t filter -X WPXQUIC 2>/dev/null || true
for s in $(ipset list -n 2>/dev/null | grep '^wpx_'); do
    ipset destroy "$s" 2>/dev/null || true
done
netfilter-persistent save 2>/dev/null || true

echo "== Removing per-device traffic accounting chains =="
iptables -t mangle -D PREROUTING -i wlan0 -j WPXACCT_UP 2>/dev/null || true
iptables -t mangle -D POSTROUTING -o wlan0 -j WPXACCT_DOWN 2>/dev/null || true
iptables -t mangle -F WPXACCT_UP 2>/dev/null || true
iptables -t mangle -X WPXACCT_UP 2>/dev/null || true
iptables -t mangle -F WPXACCT_DOWN 2>/dev/null || true
iptables -t mangle -X WPXACCT_DOWN 2>/dev/null || true

echo "== Stopping redsocks =="
systemctl disable --now redsocks 2>/dev/null || true
rm -f /etc/systemd/system/redsocks.service.d/override.conf
rmdir /etc/systemd/system/redsocks.service.d 2>/dev/null || true
systemctl daemon-reload

echo "== Removing the Wi-Fi access point connection =="
nmcli connection delete "$AP_CONN_NAME" 2>/dev/null || true

echo
echo "Done. The wired interface's static IP and installed packages (redsocks,"
echo "iptables-persistent, python3-flask, python3-pam, gunicorn, iw,"
echo "python3-dnspython, ipset, python3-qrcode) were left in place — remove/revert those"
echo "manually if you no longer want them."
