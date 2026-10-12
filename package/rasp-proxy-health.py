#!/usr/bin/env python3
"""
Root-owned periodic health check for the Wi-Fi Proxy Hotspot, run every 2
minutes by rasp-proxy-health.timer (and on demand from the admin panel's
Overview page via `systemctl start rasp-proxy-health.service`).

Checks the services, the hotspot, the firewall chains, DNS end to end,
the DNS Lookups capture, direct internet, every proxy profile (reachability
plus its exit IP/country), and the box itself (under-voltage, temperature,
disk, memory). Writes the results to /run/rasp-proxy-health/status.json
(tmpfs, group-readable by the admin app) for the Overview page.

Alerts by email (settings from the System page, see mailer.py) only on
*changes*: a problem must be seen on FAIL_AFTER_RUNS consecutive runs before
it's reported, which rides out a firewall rebuild or a restart caught
mid-check. Recovery is reported too. Some things are one-off notices
instead (box restarted, under-voltage seen in the kernel log, a proxy's
exit country changing). An email that can't be sent -- likely exactly when
the internet is what's broken -- stays queued in the persistent state file
and is retried every run, so it still arrives once things recover.

Alert-only by design: nothing here ever changes routing.

Must never print or email proxy or SMTP credentials; the proxy checks'
own results never contain them.
"""
import json
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, "/opt/rasp-proxy-admin")
from mailer import is_configured, load_alerts_config, send_email  # noqa: E402
from proxy_check import check_proxy_profile, get_exit_info  # noqa: E402

AP_IFACE = os.environ.get("RASP_PROXY_AP_IFACE", "wlan0")
AP_CONN = os.environ.get("RASP_PROXY_AP_CONN", "Gateway-AP")
PANEL_URL = os.environ.get("RASP_PROXY_PANEL_URL", "")
PROXY_STORE = "/var/lib/rasp-proxy-admin/proxies.json"
RULES_FILE = "/var/lib/rasp-proxy-admin/pattern_rules.json"
LOOKUPS_FILE = "/run/rasp-proxy-dns/lookups.json"
STATUS_DIR = "/run/rasp-proxy-health"
STATUS_FILE = f"{STATUS_DIR}/status.json"
STATE_FILE = "/var/lib/rasp-proxy-admin/health_state.json"
FAIL_AFTER_RUNS = 2
EXIT_INFO_EVERY = 1800
LOOKUPS_STALE_SECONDS = 180
PENDING_MAX = 50
PROBE_NAME = "www.google.com"
HOSTNAME = socket.gethostname()
# "off": a proxy profile that's disabled in the panel.
SEVERITY = {"off": 0, "ok": 0, "warn": 1, "fail": 2}
QUIET = ("ok", "off")


def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def check(cid, group, label, status, detail, alert=True):
    return {"id": cid, "group": group, "label": label, "status": status, "detail": detail, "alert": alert}


def when(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode, group=None):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1)
    if group is not None:
        os.chown(tmp, 0, group)
    os.replace(tmp, path)


def dns_probe(server, port, name=PROBE_NAME, timeout=4):
    # Minimal hand-built A query: dnspython would cost ~1.6s of CPU per run.
    qid = random.randint(0, 0xFFFF)
    query = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    query += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    query += struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.monotonic()
        s.sendto(query, (server, port))
        data, _ = s.recvfrom(4096)
        ms = (time.monotonic() - t0) * 1000
    except OSError as e:
        return False, f"no answer ({e.strerror or e})"
    finally:
        s.close()
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != qid:
        return False, "malformed answer"
    flags, _, answers = struct.unpack("!HHH", data[2:8])
    if flags & 0x000F:
        return False, f"error answer (rcode {flags & 0x000F})"
    if not answers:
        return False, f"empty answer for {name}"
    return True, f"answered in {ms:.0f} ms"


def check_services():
    out = []
    for unit, label in (("redsocks", "redsocks (transparent proxy)"),
                        ("rasp-proxy-dns-router", "DNS router"),
                        ("rasp-proxy-admin", "Admin panel")):
        state = run(["systemctl", "is-active", unit]).stdout.strip() or "unknown"
        out.append(check(f"svc:{unit}", "Services", label,
                         "ok" if state == "active" else "fail",
                         "Running" if state == "active" else f"Not running ({state})"))
    props = dict(line.split("=", 1) for line in run(
        ["systemctl", "show", "-p", "ActiveState", "-p", "Result", "rasp-proxy-firewall-init"]
    ).stdout.splitlines() if "=" in line)
    bad = props.get("ActiveState") == "failed" or props.get("Result", "success") != "success"
    out.append(check("svc:firewall-init", "Services", "Boot-time firewall setup",
                     "fail" if bad else "ok",
                     f"Failed ({props.get('Result', 'unknown')})" if bad else "Completed"))
    return out


def iface_ipv4(iface):
    for line in run(["ip", "-4", "-o", "addr", "show", "dev", iface]).stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            return parts[parts.index("inet") + 1].split("/")[0]
    return None


def check_hotspot():
    enabled = run(["nmcli", "-g", "connection.autoconnect", "connection", "show", AP_CONN]).stdout.strip() == "yes"
    if not enabled:
        return [check("hotspot", "Hotspot & DNS", "Wi-Fi hotspot", "ok", "Disabled by the admin", alert=False)]
    active = AP_CONN in run(["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"]).stdout.splitlines()
    if not active:
        return [check("hotspot", "Hotspot & DNS", "Wi-Fi hotspot", "fail", "Enabled but not active")]
    stations = run(["iw", "dev", AP_IFACE, "station", "dump"]).stdout.count("Station ")
    out = [check("hotspot", "Hotspot & DNS", "Wi-Fi hotspot", "ok",
                 f"Broadcasting, {stations} device{'s' if stations != 1 else ''} connected")]
    try:
        with open(f"/run/nm-dnsmasq-{AP_IFACE}.pid") as f:
            pid = int(f.read().strip())
        with open(f"/proc/{pid}/comm") as f:
            dnsmasq_ok = f.read().strip() == "dnsmasq"
    except (OSError, ValueError):
        dnsmasq_ok = False
    ap_ip = iface_ipv4(AP_IFACE)
    if not dnsmasq_ok:
        out.append(check("dns:hotspot", "Hotspot & DNS", "Hotspot DNS/DHCP", "fail", "dnsmasq isn't running"))
    elif ap_ip:
        ok, detail = dns_probe(ap_ip, 53)
        out.append(check("dns:hotspot", "Hotspot & DNS", "Hotspot DNS/DHCP", "ok" if ok else "fail", detail))
    return out


def check_dns_router():
    ok, detail = dns_probe("127.0.0.1", 15353)
    out = [check("dns:router", "Hotspot & DNS", "Pattern-rule DNS router", "ok" if ok else "fail", detail)]
    snap = load_json(LOOKUPS_FILE, None)
    if snap is None:
        status, detail = "warn", "No data from the DNS router yet"
    elif snap.get("capture") != "ok":
        status, detail = "warn", str(snap.get("capture"))[:120]
    elif time.time() - snap.get("generated", 0) > LOOKUPS_STALE_SECONDS:
        status, detail = "warn", "Not updating"
    else:
        status, detail = "ok", f"Recording ({len(snap.get('clients', {}))} devices seen)"
    out.append(check("dns:capture", "Hotspot & DNS", "DNS Lookups capture", status, detail, alert=False))
    # Proxied Lookups (proxy_doh.py): one warm-tunnel pool per proxy that a
    # rule routes through. Informational: lookups fall back to ordinary DNS.
    pools = (snap or {}).get("doh") or {}
    if pools:
        cold = [n for n, p in pools.items() if not p.get("warm")]
        parts = [f"{n}: {p.get('warm', 0)} ready, {p.get('ok', 0)} via proxy, {p.get('fallback', 0)} fallback"
                 for n, p in pools.items()]
        if cold:
            err = pools[cold[0]].get("last_error") or "no tunnel yet"
            out.append(check("dns:via-proxy", "Hotspot & DNS", "Proxied lookups", "warn",
                             f"No tunnel through {', '.join(cold)} ({err}), using ordinary DNS"[:200], alert=False))
        else:
            out.append(check("dns:via-proxy", "Hotspot & DNS", "Proxied lookups", "ok", "; ".join(parts)[:200],
                             alert=False))
    return out


def check_firewall(rules, device_policies=0):
    enabled = [r for r in rules if r.get("enabled", True)]
    expected = len(enabled) + device_policies + 2  # bypass + devices + one per rule + default
    problems = []
    nat = run(["iptables", "-t", "nat", "-S", "REDSOCKS"])
    n = sum(1 for line in nat.stdout.splitlines() if line.startswith("-A REDSOCKS"))
    if nat.returncode != 0:
        problems.append("REDSOCKS chain missing")
    elif n != expected:
        problems.append(f"REDSOCKS has {n} rules, expected {expected}")
    if run(["iptables", "-t", "nat", "-C", "PREROUTING", "-i", AP_IFACE, "-p", "tcp", "-j", "REDSOCKS"]).returncode:
        problems.append("REDSOCKS not hooked into PREROUTING")
    quic = run(["iptables", "-S", "WPXQUIC"])
    nq = sum(1 for line in quic.stdout.splitlines() if line.startswith("-A WPXQUIC"))
    if quic.returncode != 0:
        problems.append("WPXQUIC chain missing (QUIC could bypass the proxy)")
    elif nq != expected:
        problems.append(f"WPXQUIC has {nq} rules, expected {expected}")
    if run(["iptables", "-C", "FORWARD", "-i", AP_IFACE, "-p", "udp", "--dport", "443", "-j", "WPXQUIC"]).returncode:
        problems.append("WPXQUIC not hooked into FORWARD")
    sets = set(run(["ipset", "list", "-n"]).stdout.split())
    missing = [f"wpx_{r['id']}" for r in enabled if f"wpx_{r['id']}" not in sets]
    if missing:
        problems.append(f"missing ipsets: {', '.join(missing)}")
    if problems:
        return [check("firewall", "Firewall", "Routing rules", "fail", "; ".join(problems))]
    devices = f", {device_policies} device polic{'ies' if device_policies != 1 else 'y'}" if device_policies else ""
    return [check("firewall", "Firewall", "Routing rules", "ok",
                  f"{len(enabled)} pattern rule{'s' if len(enabled) != 1 else ''}{devices} + default, QUIC guard in place")]


def check_leak_guards(config):
    # Each enabled leak guard's chain must be complete and hooked in: a
    # missing one is a real leak (traffic bypassing the rules), so it alerts.
    stored = config.get("leak_guards") or {}
    guards = {k: bool(stored.get(k, True)) for k in ("dns", "private_relay", "ipv6")}
    problems = []

    def rules_in(cmd, table, chain):
        out = run([cmd, "-t", table, "-S", chain])
        return None if out.returncode else sum(1 for l in out.stdout.splitlines() if l.startswith(f"-A {chain}"))

    if guards["dns"]:
        if rules_in("iptables", "nat", "WPXDNS") != 4:
            problems.append("DNS redirect incomplete")
        if rules_in("iptables", "filter", "WPXGUARD") != 3:
            problems.append("DNS-over-TLS block incomplete")
        if run(["iptables", "-t", "nat", "-C", "PREROUTING", "-i", AP_IFACE, "-j", "WPXDNS"]).returncode:
            problems.append("DNS redirect not hooked in")
        if run(["iptables", "-C", "FORWARD", "-i", AP_IFACE, "-j", "WPXGUARD"]).returncode:
            problems.append("DNS-over-TLS block not hooked in")
    if guards["ipv6"]:
        if rules_in("ip6tables", "filter", "WPXGUARD6") != 1 or \
                run(["ip6tables", "-C", "FORWARD", "-i", AP_IFACE, "-j", "WPXGUARD6"]).returncode:
            problems.append("IPv6 block missing")
    if problems:
        return [check("guards", "Firewall", "Leak guards", "fail", "; ".join(problems))]
    on = [label for key, label in (("dns", "DNS forced through the hotspot"),
                                   ("private_relay", "Private Relay blocked"), ("ipv6", "IPv6 blocked"))
          if guards[key]]
    off = [k for k, v in guards.items() if not v]
    if not on:
        return [check("guards", "Firewall", "Leak guards", "warn", "All off: devices can route around the rules",
                      alert=False)]
    detail = ", ".join(on) + (f" ({len(off)} switched off)" if off else "")
    return [check("guards", "Firewall", "Leak guards", "ok", detail)]


def check_internet():
    t0 = time.monotonic()
    try:
        with socket.create_connection((PROBE_NAME, 443), timeout=8) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=PROBE_NAME):
                pass
        return [check("internet", "Hotspot & DNS", "Internet (direct)", "ok",
                      f"Reachable, TLS in {(time.monotonic() - t0) * 1000:.0f} ms")]
    except Exception as e:
        return [check("internet", "Hotspot & DNS", "Internet (direct)", "fail", f"Unreachable: {e}"[:160])]


def check_proxies(profiles, used, state, events):
    exits = state.setdefault("exit", {})
    now = time.time()

    def one(name):
        result = check_proxy_profile(profiles[name])
        info = None
        prev = exits.get(name, {})
        if result["ok"] and (now - prev.get("checked", 0) >= EXIT_INFO_EVERY or not prev.get("ok_last", True)):
            info = get_exit_info(profiles[name])
        return name, result, info

    out = []
    # Disabled in the panel ("monitored" was this setting's first name,
    # before the panel migrates it).
    monitored = [n for n, p in profiles.items() if p.get("enabled", p.get("monitored", True))]
    for name in profiles:
        if name not in monitored:
            detail = "Disabled, not checked"
            if name in used:
                detail += " · still used by an enabled rule, so an outage won't be reported"
            out.append(check(f"proxy:{name}", "Proxies", f'Proxy "{name}"', "off", detail, alert=False))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(one, monitored))
    for name, result, info in results:
        prev = exits.setdefault(name, {})
        if info is not None:
            # A failed lookup retries in ~5 minutes rather than waiting the full interval.
            prev["checked"] = now if "error" not in info else now - EXIT_INFO_EVERY + 300
            if "error" not in info:
                if prev.get("ip") and info["ip"] and (info["ip"], info["country"]) != (prev["ip"], prev.get("country")):
                    events.append(("NOTICE", f'Proxy "{name}" exit changed: now {info["ip"]} '
                                             f'(geolocated {info["country"] or "?"}), was {prev["ip"]} '
                                             f'({prev.get("country") or "?"}). Geo-blocked sites may stop working.'))
                prev.update({k: info[k] for k in ("ip", "country", "city", "org")})
        prev["ok_last"] = result["ok"]
        exit_text = ""
        if prev.get("ip"):
            where = ", ".join(x for x in (prev.get("city"), prev.get("country")) if x)
            exit_text = f" · exit IP {prev['ip']}" + (f", geolocated {where}" if where else "")
        in_use = name in used
        if result["ok"]:
            total = result["timings"].get("total_ms")
            detail = f"Working, {total / 1000:.1f} s round trip{exit_text}" if total else f"Working{exit_text}"
            status = "ok"
        else:
            detail = (result["error"] or "check failed")[:160]
            status = "fail" if in_use else "warn"
        if not in_use:
            detail += " · not used by any rule"
        out.append(check(f"proxy:{name}", "Proxies", f'Proxy "{name}"', status, detail, alert=in_use))
    order = list(profiles)
    out.sort(key=lambda c: order.index(c["id"][len("proxy:"):]))
    return out


def check_system(events, since):
    out = []
    volt = None
    for hw in sorted(os.listdir("/sys/class/hwmon")) if os.path.isdir("/sys/class/hwmon") else []:
        try:
            with open(f"/sys/class/hwmon/{hw}/name") as f:
                if f.read().strip() == "rpi_volt":
                    volt = f"/sys/class/hwmon/{hw}/in0_lcrit_alarm"
        except OSError:
            continue
    if volt and os.path.exists(volt):
        with open(volt) as f:
            now_low = f.read().strip() == "1"
        log = run(["journalctl", "-k", "--since", f"@{int(since)}", "-o", "cat", "--no-pager"]).stdout
        seen = log.count("Undervoltage detected")
        if seen and not now_low:
            events.append(("NOTICE", f"Under-voltage detected {seen} time{'s' if seen != 1 else ''} since "
                                     f"{when(since)}. The power supply may be failing (see the 2026-09-29 incident)."))
        if now_low:
            out.append(check("power", "System", "Power supply", "fail", "Under-voltage right now"))
        elif seen:
            out.append(check("power", "System", "Power supply", "warn",
                             f"Under-voltage seen {seen}× since the last check", alert=False))
        else:
            out.append(check("power", "System", "Power supply", "ok", "Voltage OK"))
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            temp = int(f.read().strip()) / 1000
        out.append(check("temp", "System", "CPU temperature",
                         "fail" if temp >= 85 else "warn" if temp >= 80 else "ok", f"{temp:.0f} °C"))
    except (OSError, ValueError):
        pass
    usage = shutil.disk_usage("/")
    free_pct = usage.free / usage.total * 100
    out.append(check("disk", "System", "Disk space", "fail" if free_pct < 5 else "warn" if free_pct < 10 else "ok",
                     f"{free_pct:.0f}% free ({usage.free / 2**30:.1f} GB)"))
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, value = line.split(":", 1)
                mem[key] = int(value.split()[0])
        avail = mem["MemAvailable"] / mem["MemTotal"] * 100
        out.append(check("memory", "System", "Memory", "fail" if avail < 5 else "warn" if avail < 10 else "ok",
                         f"{avail:.0f}% available ({mem['MemAvailable'] // 1024} MiB)"))
    except (OSError, KeyError, ValueError):
        pass
    return out


def read_rule_connections():
    # Connections each pattern rule's firewall entry has handled since the
    # chain was last rebuilt (every rule change rebuilds it). The nat table
    # only sees a connection's first packet, so packets == connections.
    # Shown in the panel's rules table as per-rule activity.
    counts = {}
    for line in run(["iptables", "-t", "nat", "-L", "REDSOCKS", "-n", "-v", "-x"]).stdout.splitlines():
        parts = line.split()
        match = re.search(r"match-set wpx_([0-9a-z]+) dst", line)
        if match and parts and parts[0].isdigit():
            counts[match.group(1)] = int(parts[0])
    return counts


def chain_packets(cmd, table, chain, target):
    total = 0
    for line in run([cmd, "-t", table, "-L", chain, "-n", "-v", "-x"]).stdout.splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[0].isdigit() and parts[2] == target:
            total += int(parts[0])
    return total


def read_guard_counters():
    # What each leak guard caught since the chains were last rebuilt: DNS sent
    # to an outside server (redirected) plus DNS-over-TLS attempts (rejected),
    # and forwarded IPv6. Private Relay is counted by dns_router.py instead.
    return {
        "dns": chain_packets("iptables", "nat", "WPXDNS", "REDIRECT")
        + chain_packets("iptables", "filter", "WPXGUARD", "REJECT"),
        "ipv6": chain_packets("ip6tables", "filter", "WPXGUARD6", "REJECT"),
    }


def format_email(messages, checks, now):
    problems = [m for m in messages if m["kind"] == "PROBLEM"]
    recovered = [m for m in messages if m["kind"] == "RECOVERED"]
    first = (problems or recovered or messages)[0]
    kind = "PROBLEM" if problems else "RECOVERED" if recovered else "NOTICE"
    more = f" (+{len(messages) - 1} more)" if len(messages) > 1 else ""
    subject = f"[{HOSTNAME}] {kind}: {first['text'].split(':')[0][:80]}{more}"
    lines = [f"{HOSTNAME} health check, {when(now)}", ""]
    for m in messages:
        lines.append(f"{m['kind']:<10} {when(m['time'])}  {m['text']}")
    not_ok = [c for c in checks if c["status"] not in QUIET]
    lines += ["", "Currently not OK:" if not_ok else "Everything is currently OK."]
    lines += [f"  - {c['label']}: {c['detail']}" for c in not_ok]
    if PANEL_URL:
        lines += ["", f"Admin panel: {PANEL_URL}"]
    return subject, "\n".join(lines) + "\n"


def main():
    now = time.time()
    state = load_json(STATE_FILE, {})
    state_before = json.dumps(state, sort_keys=True)
    prev_status = load_json(STATUS_FILE, {})
    events = []

    with open("/proc/sys/kernel/random/boot_id") as f:
        boot_id = f.read().strip()
    with open("/proc/uptime") as f:
        boot_time = now - float(f.read().split()[0])
    # Since when to look for kernel under-voltage messages: the previous run
    # (its status file lives in /run, so it's gone after a reboot) or boot.
    since = prev_status.get("generated") or boot_time
    alerts = load_alerts_config()
    if state.get("boot_id") != boot_id:
        if state.get("boot_id") and alerts.get("notify_boot"):
            events.append(("NOTICE", f"{HOSTNAME} restarted: up since {when(boot_time)}. "
                                     "If nobody rebooted it, suspect a power problem."))
        state["boot_id"] = boot_id

    profiles = load_json(PROXY_STORE, {}).get("profiles", {})
    config = load_json(RULES_FILE, {})
    rules = config.get("rules", [])
    used = {config.get("default_action")} | {r.get("action") for r in rules if r.get("enabled", True)}

    checks = []
    for fn in (check_services,
               check_hotspot,
               check_dns_router,
               check_internet,
               lambda: check_firewall(rules, sum(1 for mac in (config.get("device_policies") or {})
                                                 if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", str(mac).lower()))),
               lambda: check_leak_guards(config),
               lambda: check_proxies(profiles, used, state, events),
               lambda: check_system(events, since)):
        try:
            checks += fn()
        except Exception as e:  # one broken check must never hide the rest
            checks.append(check(f"internal:{getattr(fn, '__name__', 'check')}", "System", "Health check",
                                "warn", f"A check crashed: {type(e).__name__}: {e}"[:160], alert=False))

    prev = state.get("checks", {})
    new_state, messages = {}, []
    for c in checks:
        p = prev.get(c["id"], {})
        bad = c["status"] not in QUIET
        c["since"] = p.get("since", now) if p.get("status") == c["status"] else now
        # Capped: past the threshold the count no longer matters, and letting
        # it grow would rewrite the state file (SD card) on every run for as
        # long as something stays down.
        bad_runs = min(p.get("bad_runs", 0) + 1, FAIL_AFTER_RUNS) if bad else 0
        bad_since = (p.get("bad_since") or now) if bad else None
        alerting = p.get("alerting", False) and c["alert"]
        if bad and c["alert"] and not alerting and bad_runs >= FAIL_AFTER_RUNS:
            alerting = True
            messages.append({"kind": "PROBLEM", "time": now, "text": f"{c['label']}: {c['detail']}"})
        elif not bad and alerting:
            alerting = False
            down = (now - p.get("bad_since", now)) / 60
            messages.append({"kind": "RECOVERED", "time": now,
                             "text": f"{c['label']}: {c['detail']} (was down about {down:.0f} min)"})
        new_state[c["id"]] = {"status": c["status"], "since": c["since"], "bad_runs": bad_runs,
                              "bad_since": bad_since, "alerting": alerting}
    state["checks"] = new_state
    messages += [{"kind": kind, "time": now, "text": text} for kind, text in events]

    enabled = alerts.get("enabled") and is_configured(alerts)
    pending = (state.get("pending", []) + messages)[-PENDING_MAX:] if enabled else []
    delivery = state.setdefault("delivery", {})
    if pending:
        subject, body = format_email(pending, checks, now)
        error = send_email(alerts, subject, body)
        if error:
            delivery["last_error"] = error  # no timestamp: it would change the state file every run
            print(f"rasp-proxy-health: alert email not sent, will retry: {error}", file=sys.stderr)
        else:
            delivery["last_sent"], delivery["last_error"] = now, None
            pending = []
    state["pending"] = pending

    worst = max((SEVERITY[c["status"]] for c in checks), default=0)
    status = {
        "generated": now,
        "hostname": HOSTNAME,
        "overall": {0: "ok", 1: "warn", 2: "fail"}[worst],
        "checks": checks,
        "alerts": {"enabled": bool(enabled), "pending": len(pending), **delivery},
        "rule_connections": read_rule_connections(),
        "guard_counters": read_guard_counters(),
    }
    try:
        import grp

        group = grp.getgrnam("redsocks").gr_gid
    except (ImportError, KeyError):
        group = None
    os.makedirs(STATUS_DIR, exist_ok=True)
    if group is not None:
        os.chown(STATUS_DIR, 0, group)
    os.chmod(STATUS_DIR, 0o750)
    write_json(STATUS_FILE, status, 0o640, group)
    # Only touch the SD card when something actually changed.
    if json.dumps(state, sort_keys=True) != state_before:
        write_json(STATE_FILE, state, 0o600)


if __name__ == "__main__":
    main()
