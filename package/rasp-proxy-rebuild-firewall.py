#!/usr/bin/env python3
"""
Root-owned helper: rebuilds the REDSOCKS iptables chain from scratch —
the internal bypass CIDR (always wins), then the ordered pattern rules
(each matching against its own ipset, populated in real time by
dns_router.py, each an explicit override), then the configurable global
default for everything else — and persists the result. Always rebuilds
the whole chain in one pass so the firewall can never be left in a state
that reflects only half of the admin's configuration.

Per-device policies (Devices page) come right after the bypass CIDR and
before every pattern rule, matched by MAC address: a device set to "always
direct" or "always through <profile>" ignores the pattern rules entirely.

Every rule's and the default's "action" is either the literal string
"direct" or the name of a saved proxy profile (see proxies.json) — each
profile has its own permanent local redsocks port, so different rules can
route through different upstream proxies simultaneously. An action
referencing a profile that no longer exists is treated as "direct"
(fail-safe) rather than erroring the whole rebuild.

Also rebuilds a companion filter-table chain, WPXQUIC, from the same
config in the same order: wherever REDSOCKS would send TCP to a proxy,
WPXQUIC rejects UDP/443 (QUIC / HTTP/3). redsocks only relays TCP, so
without this a browser or app using QUIC to a "proxied" destination
bypasses the proxy entirely and exposes the real public IP -- confirmed
live 2026-09-30: RaiPlay live streams failed geo-checks even with every
default routed through the proxy, until QUIC was blocked. The reject makes
clients fall back to TCP, which REDSOCKS does catch. Destinations routed
direct keep QUIC.

Also rebuilds the leak guards (see rebuild_guards): forced DNS, DNS-over-TLS
blocked, IPv6 blocked -- the ways a device could otherwise route around the
pattern rules without anyone noticing.

Also prunes any ipset left behind by a rule that has since been deleted
or edited — deleting a rule drops its firewall reference but never its
ipset on its own, so this is the one place that cleans those up.

Finally, clears the hotspot dnsmasq's DNS cache (SIGHUP). dns_router.py
only tags IPs when a lookup actually reaches it, and a lookup dnsmasq
answers from its own cache never does -- confirmed live 2026-10-01 (first
lookup ~70-100ms via dns_router, repeats ~2ms from dnsmasq's cache). So
without this a newly added rule would miss every name dnsmasq already has
cached, until that name's real TTL expired. Paired with dnsmasq's
max-ttl=60 (see install.sh), which makes clients re-ask within a minute.

bypass_cidr is read from pattern_rules.json (not passed as an argument)
so this script can also run unattended at boot, before the admin app
itself is even running — this is also what makes it the reliable way to
restore the firewall after a reboot: netfilter-persistent saves iptables
rules but never ipset contents, so a saved rule referencing a since-
vanished ipset makes the *entire* saved ruleset fail to restore
atomically (iptables-restore is all-or-nothing). Rebuilding fresh from
this authoritative JSON state, ipsets included, sidesteps that entirely.

Invoked by the admin web app via a narrowly-scoped sudo rule (see
sudoers.template) whenever the bypass CIDR, the default action, the
pattern-rule list, or the proxy-profile list changes, and by
rasp-proxy-firewall-init.service on every boot.

Usage: rasp-proxy-rebuild-firewall <ap_iface>
"""
import json
import os
import re
import signal
import subprocess
import sys

CIDR_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}/([0-9]|[1-2][0-9]|3[0-2])$")
IFACE_RE = re.compile(r"[A-Za-z0-9_-]{1,15}")
PROXY_STORE = "/var/lib/rasp-proxy-admin/proxies.json"
RULES_FILE = "/var/lib/rasp-proxy-admin/pattern_rules.json"
IPSET_TIMEOUT = "86400"


def load_profiles():
    try:
        with open(PROXY_STORE) as f:
            return json.load(f).get("profiles", {})
    except (OSError, ValueError):
        return {}


def load_config():
    try:
        with open(RULES_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    rules = []
    for r in data.get("rules", []):
        if not r.get("enabled", True):
            # Disabled rules are skipped entirely, as if they didn't exist:
            # no chain rule, and their ipset (if any) is left out of the
            # active set below, so prune_orphaned_ipsets() cleans it up.
            continue
        rule = dict(r)
        rule["ipset"] = f"wpx_{r['id']}"
        rules.append(rule)
    return data.get("bypass_cidr", ""), data.get("default_action", "direct"), rules


MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


def load_device_policies():
    # Per-device routing (Devices page): MAC -> "direct" or a profile name.
    # Matched by MAC so it survives the device getting a new DHCP address,
    # and placed ahead of every pattern rule, so a device policy always wins.
    try:
        with open(RULES_FILE) as f:
            stored = json.load(f).get("device_policies") or {}
    except (OSError, ValueError):
        stored = {}
    return sorted((mac.lower(), action) for mac, action in stored.items()
                  if isinstance(mac, str) and MAC_RE.fullmatch(mac.lower()) and isinstance(action, str))


def resolve_target(action, profiles):
    # Fail-safe: "direct", or any action referencing a profile that no
    # longer exists, is treated as RETURN rather than erroring out.
    if action != "direct" and action in profiles:
        return "REDIRECT", profiles[action]["local_port"]
    return "RETURN", None


def ensure_ipset(name):
    subprocess.run(
        ["ipset", "create", name, "hash:ip", "family", "inet", "timeout", IPSET_TIMEOUT, "-exist"],
        check=True,
    )


def prune_orphaned_ipsets(active_names):
    # Deleting a rule removes its firewall reference but never its ipset;
    # clean up anything left behind by a rule that no longer exists, now
    # that the chain above has already stopped referencing it.
    listed = subprocess.run(["ipset", "list", "-n"], capture_output=True, text=True)
    for name in listed.stdout.split():
        if name.startswith("wpx_") and name not in active_names:
            subprocess.run(["ipset", "destroy", name], capture_output=True)


def add_rule(match_args, target, port):
    cmd = ["iptables", "-t", "nat", "-A", "REDSOCKS"]
    if target == "REDIRECT":
        # REDIRECT --to-ports requires an explicit port-capable protocol
        # match on this specific rule; it isn't inherited from the chain.
        cmd += ["-p", "tcp"]
    cmd += match_args
    cmd += ["-j", target]
    if target == "REDIRECT":
        cmd += ["--to-ports", str(port)]
    subprocess.run(cmd, check=True)


def add_quic_rule(match_args, target):
    # REDIRECT (proxied) -> reject QUIC so the client retries over TCP;
    # RETURN (direct) -> leave QUIC alone.
    cmd = ["iptables", "-t", "filter", "-A", "WPXQUIC"] + match_args
    if target == "REDIRECT":
        cmd += ["-j", "REJECT", "--reject-with", "icmp-port-unreachable"]
    else:
        cmd += ["-j", "RETURN"]
    subprocess.run(cmd, check=True)


def rebuild_quic_chain(ap_iface, bypass_cidr, rules, default_action, profiles, device_policies=()):
    subprocess.run(["iptables", "-t", "filter", "-N", "WPXQUIC"], capture_output=True)
    subprocess.run(["iptables", "-t", "filter", "-F", "WPXQUIC"], check=True)
    subprocess.run(
        ["iptables", "-t", "filter", "-A", "WPXQUIC", "-d", bypass_cidr, "-j", "RETURN"],
        check=True,
    )
    for mac, action in device_policies:
        target, _ = resolve_target(action, profiles)
        add_quic_rule(["-m", "mac", "--mac-source", mac], target)
    for rule in rules:
        target, _ = resolve_target(rule["action"], profiles)
        add_quic_rule(["-m", "set", "--match-set", rule["ipset"], "dst"], target)
    default_target, _ = resolve_target(default_action, profiles)
    add_quic_rule([], default_target)

    hook = ["FORWARD", "-i", ap_iface, "-p", "udp", "--dport", "443", "-j", "WPXQUIC"]
    check = subprocess.run(["iptables", "-t", "filter", "-C"] + hook, capture_output=True)
    if check.returncode != 0:
        # Inserted at the top so no earlier FORWARD ACCEPT can shadow it.
        subprocess.run(["iptables", "-t", "filter", "-I", hook[0], "1"] + hook[1:], check=True)


GUARD_DEFAULTS = {"dns": True, "private_relay": True, "ipv6": True}


def load_guards():
    try:
        with open(RULES_FILE) as f:
            stored = json.load(f).get("leak_guards") or {}
    except (OSError, ValueError):
        stored = {}
    return {k: bool(stored.get(k, v)) for k, v in GUARD_DEFAULTS.items()}


def ensure_hook(cmd, table, chain_args):
    # Insert `chain_args` at the top of its built-in chain, unless already present.
    if subprocess.run([cmd, "-t", table, "-C"] + chain_args, capture_output=True).returncode != 0:
        subprocess.run([cmd, "-t", table, "-I", chain_args[0], "1"] + chain_args[1:], check=True)


def rebuild_guards(ap_iface, bypass_cidr, guards):
    """Leak guards (Routing Rules page), so devices can't route around the
    pattern rules. Chains always exist and stay hooked; a guard that's off
    just leaves its chain empty.
      WPXDNS (nat): plain DNS to any outside resolver -> the hotspot's own DNS.
      WPXGUARD (filter): DNS-over-TLS / DNS-over-QUIC (port 853) rejected, so
        e.g. Android's "Private DNS: Automatic" falls back to plain DNS.
      WPXGUARD6 (ip6tables filter): all forwarded IPv6 rejected; redsocks and
        every chain above are IPv4-only, so IPv6 would bypass them all.
    The internal bypass range is exempt, as everywhere else. Private Relay
    and Firefox's DoH canary are answered by dns_router.py instead."""
    subprocess.run(["iptables", "-t", "nat", "-N", "WPXDNS"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-F", "WPXDNS"], check=True)
    subprocess.run(["iptables", "-t", "filter", "-N", "WPXGUARD"], capture_output=True)
    subprocess.run(["iptables", "-t", "filter", "-F", "WPXGUARD"], check=True)
    if guards["dns"]:
        nat = ["iptables", "-t", "nat", "-A", "WPXDNS"]
        # Queries already addressed to this box leave first, so the REDIRECT
        # counters (shown in the panel) count only outside-resolver lookups.
        subprocess.run(nat + ["-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"], check=True)
        subprocess.run(nat + ["-d", bypass_cidr, "-j", "RETURN"], check=True)
        for proto in ("udp", "tcp"):
            # REDIRECT goes to the incoming interface's own address, where the
            # hotspot's dnsmasq listens.
            subprocess.run(nat + ["-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"], check=True)
        flt = ["iptables", "-t", "filter", "-A", "WPXGUARD"]
        subprocess.run(flt + ["-d", bypass_cidr, "-j", "RETURN"], check=True)
        subprocess.run(flt + ["-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"], check=True)
        subprocess.run(flt + ["-p", "udp", "--dport", "853", "-j", "REJECT", "--reject-with",
                              "icmp-port-unreachable"], check=True)
    # Top of PREROUTING: before the REDSOCKS hook, which would otherwise grab TCP DNS.
    ensure_hook("iptables", "nat", ["PREROUTING", "-i", ap_iface, "-j", "WPXDNS"])
    ensure_hook("iptables", "filter", ["FORWARD", "-i", ap_iface, "-j", "WPXGUARD"])

    # Best-effort: a box without ip6tables simply has no IPv6 guard.
    try:
        subprocess.run(["ip6tables", "-t", "filter", "-N", "WPXGUARD6"], capture_output=True)
        subprocess.run(["ip6tables", "-t", "filter", "-F", "WPXGUARD6"], check=True, capture_output=True)
        if guards["ipv6"]:
            subprocess.run(["ip6tables", "-t", "filter", "-A", "WPXGUARD6", "-j", "REJECT", "--reject-with",
                            "icmp6-adm-prohibited"], check=True)
        ensure_hook("ip6tables", "filter", ["FORWARD", "-i", ap_iface, "-j", "WPXGUARD6"])
    except (OSError, subprocess.CalledProcessError):
        print("rasp-proxy-rebuild-firewall: no ip6tables, IPv6 guard not applied", file=sys.stderr)


def flush_dns_cache(ap_iface):
    # NetworkManager's shared-mode dnsmasq for this interface. SIGHUP
    # clears its cache without touching DHCP leases. Best-effort: at boot
    # it may not be running yet (nothing is cached then anyway), and the
    # comm check guards against a stale pidfile naming a reused PID.
    try:
        with open(f"/run/nm-dnsmasq-{ap_iface}.pid") as f:
            pid = int(f.read().strip())
        with open(f"/proc/{pid}/comm") as f:
            if f.read().strip() != "dnsmasq":
                return
        os.kill(pid, signal.SIGHUP)
    except (OSError, ValueError):
        pass


def main():
    if len(sys.argv) != 2:
        sys.exit(2)
    ap_iface = sys.argv[1]
    if not IFACE_RE.fullmatch(ap_iface):
        sys.exit(3)

    profiles = load_profiles()
    bypass_cidr, default_action, rules = load_config()
    if not CIDR_RE.fullmatch(bypass_cidr):
        sys.exit(4)
    for rule in rules:
        ensure_ipset(rule["ipset"])

    subprocess.run(["iptables", "-t", "nat", "-N", "REDSOCKS"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-F", "REDSOCKS"], check=True)

    subprocess.run(
        ["iptables", "-t", "nat", "-A", "REDSOCKS", "-d", bypass_cidr, "-j", "RETURN"],
        check=True,
    )

    device_policies = load_device_policies()
    for mac, action in device_policies:
        target, port = resolve_target(action, profiles)
        add_rule(["-m", "mac", "--mac-source", mac], target, port)

    for rule in rules:
        target, port = resolve_target(rule["action"], profiles)
        add_rule(["-m", "set", "--match-set", rule["ipset"], "dst"], target, port)

    default_target, default_port = resolve_target(default_action, profiles)
    add_rule([], default_target, default_port)

    check = subprocess.run(
        ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", ap_iface, "-p", "tcp", "-j", "REDSOCKS"],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", ap_iface, "-p", "tcp", "-j", "REDSOCKS"],
            check=True,
        )

    # After REDSOCKS on purpose: if this fails partway, the worst case is
    # QUIC leaking past the proxy (the pre-fix behaviour), never a broken
    # REDSOCKS chain.
    rebuild_quic_chain(ap_iface, bypass_cidr, rules, default_action, profiles, device_policies)
    # Last for the same reason: a failure here only leaves a guard missing.
    rebuild_guards(ap_iface, bypass_cidr, load_guards())

    subprocess.run(["netfilter-persistent", "save"], check=True)
    prune_orphaned_ipsets({rule["ipset"] for rule in rules})
    flush_dns_cache(ap_iface)


if __name__ == "__main__":
    main()
