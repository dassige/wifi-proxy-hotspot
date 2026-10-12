#!/usr/bin/env python3
"""
Root-owned helper: keeps two mangle-table chains (WPXACCT_UP, WPXACCT_DOWN)
in sync with the current set of connected-device IPs, for lightweight
per-device traffic accounting.

WPXACCT_UP is hooked from mangle PREROUTING (-i <ap_iface>) and counts
upload bytes by matching each device's source IP, before any REDSOCKS
redirect decision is made — so it counts proxied and direct traffic alike.
WPXACCT_DOWN is hooked from mangle POSTROUTING (-o <ap_iface>) and counts
download bytes by matching each device's destination IP; this chain sees
both forwarded replies (direct traffic) and locally-generated replies from
redsocks itself (proxied traffic), since both leave via the same interface
on their way back to the device. One hook point per direction is enough to
cover the whole gateway, regardless of which path a given connection took.

Each device gets exactly one counting rule (`-j RETURN`) per chain; the
counter is free (a kernel increment already happening for every packet
this box forwards or proxies), so this stays cheap even on modest
hardware. A device that leaves has its rule removed the next time this
script runs (its accumulated count is not preserved) — these counters are
deliberately NOT persisted across a reboot and are not wired into
netfilter-persistent. That is intentional, not the same gap as the
REDSOCKS chain (see rasp-proxy-rebuild-firewall.py's docstring): these are
live session stats, rebuilt fresh and cheaply from scratch by the admin
app itself on its next page render, not policy state that needs to survive
unattended. There is nothing here that needs to work before anything else
starts.

Invoked by the admin web app via a narrowly-scoped sudo rule (see
sudoers.template) every time the Connected Devices list is fetched.

Usage: rasp-proxy-traffic-sync <ap_iface> [device_ip ...]
"""
import re
import subprocess
import sys

IFACE_RE = re.compile(r"[A-Za-z0-9_-]{1,15}")
IP_RE = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")
CHAIN_UP = "WPXACCT_UP"
CHAIN_DOWN = "WPXACCT_DOWN"


def valid_ip(ip):
    m = IP_RE.fullmatch(ip)
    return m is not None and all(0 <= int(o) <= 255 for o in m.groups())


def ensure_chain_and_hook(chain, base_chain, hook_args):
    subprocess.run(["iptables", "-t", "mangle", "-N", chain], capture_output=True)
    check = subprocess.run(
        ["iptables", "-t", "mangle", "-C", base_chain, *hook_args, "-j", chain],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-t", "mangle", "-A", base_chain, *hook_args, "-j", chain],
            check=True,
        )


def current_rule_ips(chain, match_flag):
    # Parse `iptables -S`, which prints one exact rule-spec line per rule
    # (e.g. "-A WPXACCT_UP -s 192.168.4.50/32 -j RETURN"), rather than the
    # column-aligned `-L` output, since it's unambiguous to match on.
    out = subprocess.run(
        ["iptables", "-t", "mangle", "-S", chain], capture_output=True, text=True
    )
    ips = set()
    pattern = re.compile(rf"{match_flag} (\d{{1,3}}(?:\.\d{{1,3}}){{3}})(?:/32)?\b")
    for line in out.stdout.splitlines():
        m = pattern.search(line)
        if m:
            ips.add(m.group(1))
    return ips


def sync_chain(chain, match_flag, desired_ips):
    existing = current_rule_ips(chain, match_flag)
    for ip in desired_ips - existing:
        subprocess.run(
            ["iptables", "-t", "mangle", "-A", chain, match_flag, ip, "-j", "RETURN"],
            check=True,
        )
    for ip in existing - desired_ips:
        subprocess.run(
            ["iptables", "-t", "mangle", "-D", chain, match_flag, ip, "-j", "RETURN"],
            capture_output=True,
        )


def main():
    if len(sys.argv) < 2:
        sys.exit(2)
    ap_iface = sys.argv[1]
    if not IFACE_RE.fullmatch(ap_iface):
        sys.exit(3)

    device_ips = set(sys.argv[2:])
    for ip in device_ips:
        if not valid_ip(ip):
            sys.exit(4)

    ensure_chain_and_hook(CHAIN_UP, "PREROUTING", ["-i", ap_iface])
    ensure_chain_and_hook(CHAIN_DOWN, "POSTROUTING", ["-o", ap_iface])

    sync_chain(CHAIN_UP, "-s", device_ips)
    sync_chain(CHAIN_DOWN, "-d", device_ips)


if __name__ == "__main__":
    main()
