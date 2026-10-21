import base64
import io
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, render_template, request, send_file

from help_texts import (  # noqa: F401  (passed to the templates in render())
    HELP_PROXY_PROFILES,
    HELP_WIFI,
    HELP_INTERNAL_NETWORK,
    HELP_DEFAULT_BEHAVIOUR,
    HELP_PATTERN_RULES,
    HELP_DEVICES,
    HELP_OVERVIEW,
    HELP_ALERTS,
    HELP_LEAK_GUARDS,
    HELP_RESOLVE_VIA_PROXY,
    HELP_LOOKUPS,
    HELP_BACKUP_RESTORE,
    HELP_SYSTEM,
    HELP_HELP,
)
from mailer import DEFAULTS as _MAILER_DEFAULTS, LIMITS as _MAILER_LIMITS, load_alerts_config, save_alerts_config, send_email
from pattern_match import match_rule, matching_pattern, prepare_rule, rule_patterns
from proxy_check import check_proxy_profile

app = Flask(__name__)
# Templates (templates/) render exactly as written, final newline included.
app.jinja_env.keep_trailing_newline = True

# All site-specific values are read from the environment (set by the systemd
# unit installed by install.sh) so this file never needs editing per-install.
ALLOWED_USERS = {
    u.strip()
    for u in os.environ.get("RASP_PROXY_ADMIN_USERS", "admin").split(",")
    if u.strip()
}
AP_CONN_NAME = os.environ.get("RASP_PROXY_AP_CONN", "Gateway-AP")
AP_IFACE = os.environ.get("RASP_PROXY_AP_IFACE", "wlan0")


def _read_version():
    # version.json is generated from pyproject.toml and deployed next to this
    # file by install.sh and deploy.sh, so it always describes the code that's
    # actually running. The systemd unit's environment (set once, at install
    # time) is only a fallback: it went stale as soon as the first update was
    # deployed by hand, showing 1.11.2 while 1.14.0 ran.
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "version.json")) as f:
            v = json.load(f)
        return str(v["version"]), str(v["date"])
    except (OSError, ValueError, KeyError, TypeError):
        return (os.environ.get("RASP_PROXY_VERSION", "unknown"),
                os.environ.get("RASP_PROXY_VERSION_DATE", "unknown"))


APP_VERSION, APP_VERSION_DATE = _read_version()

PAMCHECK_HELPER = "/usr/local/sbin/rasp-proxy-pamcheck"
REBUILD_FIREWALL_HELPER = "/usr/local/sbin/rasp-proxy-rebuild-firewall"
TRAFFIC_SYNC_HELPER = "/usr/local/sbin/rasp-proxy-traffic-sync"
REDSOCKS_CONF = "/etc/redsocks.conf"
PROXY_STORE = "/var/lib/rasp-proxy-admin/proxies.json"
PATTERN_RULES_FILE = "/var/lib/rasp-proxy-admin/pattern_rules.json"
DEVICES_STORE = "/var/lib/rasp-proxy-admin/devices.json"
# Deployed by install.sh alongside this file (Step 7), not fetched from the
# internet, so the Help page still works on a box with no internet access.
GUIDE_PDF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Wi-Fi-Proxy-Hotspot-Guide.pdf")
LEASE_FILE = f"/var/lib/NetworkManager/dnsmasq-{AP_IFACE}.leases"
CIDR_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}/([0-9]|[1-2][0-9]|3[0-2])$")
PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9 _-]{1,40}")
PATTERN_MODES = ("match", "wildcard", "regexp")
MAX_PATTERNS_PER_RULE = 50
MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
NICKNAME_MAX = 40
# Ways a device could route around the pattern rules, each blocked unless
# switched off on the Routing Rules page (all on by default).
LEAK_GUARDS = {
    "dns": ("Force all DNS through the hotspot",
            "Plain DNS sent to any outside server (e.g. a TV or Chromecast hard-wired to 8.8.8.8) is "
            "answered by the hotspot instead, and encrypted DNS-over-TLS (port 853) is blocked so "
            "phones fall back to plain DNS. Firefox is told not to use its own DNS-over-HTTPS."),
    "private_relay": ("Block iCloud Private Relay",
                      "Private Relay would carry an iPhone's or Mac's Safari traffic past every rule. "
                      "Apple devices then show \"Private Relay is turned off for this network\"."),
    "ipv6": ("Block IPv6 from hotspot devices",
             "Proxying and pattern rules work over IPv4 only, so any IPv6 traffic would bypass them. "
             "The hotspot has no IPv6 today; this keeps it that way if the router or settings change."),
}
# Ready-made multi-pattern rules, offered in the Add Routing Rule form. Only
# services whose hostnames were actually verified on this box belong here:
# a wrong guess would silently fail to proxy part of a service. For anything
# else, use the DNS Lookups page to find the real hostnames.
RULE_PRESETS = {
    "raiplay": {
        "label": "RaiPlay (on demand and live channels)",
        "description": "RaiPlay",
        # Site; live-channel CDNs (verified 2026-09-30: netrw for most channels,
        # MainStreaming's msvdn for others); and the stream "relinker", which
        # was only proxied by sharing an Akamai IP with www.raiplay.it until
        # Proxied Lookups gave the two different answers (2026-10-01).
        "patterns": ["*raiplay.it", "*.netrw.it", "*.msvdn.net", "mediapolis.rai.it"],
    },
    "tv8": {
        "label": "TV8 (site and live stream)",
        "description": "TV8",
        # Site, and the live HLS stream's Akamai host (verified 2026-10-01).
        "patterns": ["*tv8.it", "*skycdn-it.akamaized.net"],
    },
}
BASE_LOCAL_PORT = 20000
# Written every 2 minutes by rasp-proxy-health (a root timer), read by the Overview page.
HEALTH_STATUS_FILE = "/run/rasp-proxy-health/status.json"
HEALTH_STALE_SECONDS = 600
EMAIL_RE = re.compile(r"[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+")
SMTP_HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")
# Written by dns_router.py (see its capture thread), read by the DNS Lookups page.
LOOKUPS_FILE = "/run/rasp-proxy-dns/lookups.json"
LOOKUPS_STALE_SECONDS = 180
HOSTNAME_RE = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")
# CDN domains shared by thousands of unrelated sites: a "*.<domain>" rule for
# one of these would send far more than the intended service through a
# proxy, so the suggested rule for a name under them is the exact hostname.
SHARED_CDN_DOMAINS = {
    "akamaized.net", "akamaihd.net", "akamaiedge.net", "edgekey.net", "edgesuite.net",
    "cloudfront.net", "fastly.net", "fastlylb.net", "azureedge.net", "llnwd.net",
    "b-cdn.net", "edgecastcdn.net", "cdn77.org", "googlevideo.com", "amazonaws.com",
    "cloudflare.net", "footprint.net",
}
# Second-level labels under which the registrable domain is three labels,
# e.g. bbc.co.uk, abc.net.au -- a rough stand-in for the Public Suffix List.
SECOND_LEVEL_LABELS = {"co", "com", "net", "org", "gov", "ac", "edu", "gv", "or", "ne", "govt", "geek"}


def pam_authenticate(username, password):
    # unix_chkpwd (used internally by pam_unix) refuses to verify another
    # user's password unless the calling process is root, so the actual PAM
    # check runs in a dedicated root-owned helper via a narrowly-scoped sudo
    # rule. Password is passed over stdin, never as an argv value, so it
    # never appears in `ps` output or sudo logs.
    if username not in ALLOWED_USERS:
        return False
    try:
        result = subprocess.run(
            ["sudo", "-n", PAMCHECK_HELPER, username],
            input=password.encode(),
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            app.logger.warning(
                "PAM auth failed for user=%s (helper exit %s): %s",
                username,
                result.returncode,
                result.stderr.decode(errors="replace").strip(),
            )
        return result.returncode == 0
    except Exception as e:
        app.logger.warning("PAM auth error for user=%s: %s", username, e)
        return False


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not pam_authenticate(auth.username, auth.password):
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Wi-Fi Proxy Hotspot Administration"'},
            )
        return f(*args, **kwargs)

    return wrapper


def _parse_existing_redsocks_conf():
    # Used only once, to seed the profile store from whatever redsocks.conf
    # already had on disk the first time this app runs against it.
    text = open(REDSOCKS_CONF).read()

    def find(key, default=""):
        m = re.search(rf'\b{key}\b\s*=\s*"?([^;"\n]+)"?\s*;', text)
        return m.group(1).strip() if m else default

    return {
        "description": "Migrated from existing configuration",
        "type": find("type", "http-connect"),
        "ip": find("ip"),
        "port": find("port"),
        "login": find("login"),
        "password": find("password"),
    }


def load_store():
    if os.path.exists(PROXY_STORE):
        with open(PROXY_STORE) as f:
            store = json.load(f)
        is_new = False
    else:
        store = {"profiles": {"default": _parse_existing_redsocks_conf()}}
        is_new = True

    store.setdefault("next_port", BASE_LOCAL_PORT)
    store.pop("active", None)  # superseded by per-rule/default profile references
    changed = is_new
    for profile in store["profiles"].values():
        if "local_port" not in profile:
            profile["local_port"] = store["next_port"]
            store["next_port"] += 1
            changed = True
    migrated = False
    for profile in store["profiles"].values():
        if "monitored" in profile:  # the toggle's name for its first few hours (2026-10-01)
            profile.setdefault("enabled", profile["monitored"])
            del profile["monitored"]
            migrated = True
    if changed:
        save_store(store)
    elif migrated:
        save_store(store, apply_to_redsocks=False)
    return store


def save_store(store, apply_to_redsocks=True):
    # apply_to_redsocks=False is for settings redsocks doesn't use (such as
    # "enabled"), so changing them doesn't restart redsocks and drop every
    # proxied connection.
    os.makedirs(os.path.dirname(PROXY_STORE), exist_ok=True)
    with open(PROXY_STORE, "w") as f:
        json.dump(store, f, indent=2)
    os.chmod(PROXY_STORE, 0o660)
    if apply_to_redsocks:
        write_redsocks_conf_all(store["profiles"])


def write_redsocks_conf_all(profiles):
    # One redsocks{} block per saved profile, each on its own permanent
    # local port, so different pattern rules/the default can each pick a
    # different upstream proxy simultaneously (redsocks supports this
    # natively within a single config/daemon instance).
    blocks = []
    for p in profiles.values():
        blocks.append(
            "redsocks {\n"
            "    local_ip = 0.0.0.0;\n"
            f"    local_port = {p['local_port']};\n"
            f"    ip = {p['ip']};\n"
            f"    port = {p['port']};\n"
            f"    type = {p['type']};\n"
            f"    login = \"{p['login']}\";\n"
            f"    password = \"{p['password']}\";\n"
            "}"
        )
    conf = (
        "base {\n"
        "    log_debug = off;\n"
        "    log_info = on;\n"
        '    log = "syslog:daemon";\n'
        "    daemon = on;\n"
        "    redirector = iptables;\n"
        "}\n\n" + "\n\n".join(blocks) + "\n"
    )
    with open(REDSOCKS_CONF, "w") as f:
        f.write(conf)
    subprocess.run(["sudo", "-n", "/usr/bin/systemctl", "restart", "redsocks"], check=True)


def get_action_choices():
    store = load_store()
    choices = [("direct", "Direct (bypass the proxy)")]
    for name, p in store["profiles"].items():
        label = f"{name} — {p['description']}" if p.get("description") else name
        if not p.get("enabled", True):
            label += " (disabled)"
        choices.append((name, label))
    return choices


def upsert_proxy_profile(name, description, proxy_type, ip, port, login, password):
    store = load_store()
    existing = store["profiles"].get(name)
    if not password and existing:
        password = existing["password"]
    if existing:
        local_port = existing["local_port"]
    else:
        local_port = store["next_port"]
        store["next_port"] += 1

    store["profiles"][name] = {
        "description": description,
        "type": proxy_type,
        "ip": ip,
        "port": port,
        "login": login,
        "password": password,
        "local_port": local_port,
        "enabled": existing.get("enabled", True) if existing else True,
    }
    save_store(store)


def restorable(name, remembered, config):
    # What disabling `name` switched off that can still be put back: rules
    # that still exist, still use it and are still off; devices that haven't
    # been given another routing setting since.
    rule_ids = set(remembered.get("rules") or [])
    rules = [r["id"] for r in config["rules"]
             if r["id"] in rule_ids and r["action"] == name and not r.get("enabled", True)]
    devices = [mac for mac in remembered.get("devices") or []
               if isinstance(mac, str) and mac not in config.get("device_policies", {})]
    return {"rules": rules, "devices": devices}


def restore_labels(name, profile, config):
    # Human-readable list for the re-enable confirmation.
    pending = restorable(name, profile.get("disabled_with") or {}, config)
    known = load_devices_store()
    labels = [f"rule: {rule_label(r)}" for r in config["rules"] if r["id"] in pending["rules"]]
    labels += [f"device: {device_label(known.get(m, {}).get('nickname'), known.get(m, {}).get('hostname'), mac=m)}"
               for m in pending["devices"]]
    return labels


def set_profile_enabled(name, enabled, restore=False):
    """Returns (message, error). A disabled profile isn't health-checked or
    alerted on (see rasp-proxy-health), and every enabled pattern rule that
    routes through it is switched off with it, so nothing keeps going through
    a proxy nobody is watching. It's refused while the profile is the
    Default Behaviour, which has no off switch. What it switched off is
    remembered ("disabled_with"); re-enabling puts it back only if asked
    (restore=True, after a confirmation on the page)."""
    store = load_store()
    if name not in store["profiles"]:
        return None, "Unknown proxy profile"
    if enabled:
        profile = store["profiles"][name]
        profile["enabled"] = True
        remembered = profile.pop("disabled_with", None) or {}
        save_store(store, apply_to_redsocks=False)
        if not restore:
            pending = restorable(name, remembered, load_pattern_config())
            if pending["rules"] or pending["devices"]:
                return (f'Proxy profile "{name}" enabled. What was switched off with it stays off: turn '
                        "rules back on under Routing Rules, and devices on the Devices page."), None
            return f'Proxy profile "{name}" enabled.', None
        config = load_pattern_config()
        pending = restorable(name, remembered, config)
        for r in config["rules"]:
            if r["id"] in pending["rules"]:
                r["enabled"] = True
        for mac in pending["devices"]:
            config["device_policies"][mac] = name
        if pending["rules"] or pending["devices"]:
            save_pattern_config(config)  # one firewall rebuild for all of it
        parts = []
        if pending["rules"]:
            parts.append(f"{len(pending['rules'])} rule{'s' if len(pending['rules']) != 1 else ''} switched back on")
        if pending["devices"]:
            parts.append(f"{len(pending['devices'])} device{'s' if len(pending['devices']) != 1 else ''} "
                         "routed through it again")
        return f'Proxy profile "{name}" enabled' + (f": {' and '.join(parts)}." if parts else "."), None

    config = load_pattern_config()
    if config["default_action"] == name:
        return None, (f'Can\'t disable "{name}": it\'s the Default Behaviour. Point the default at '
                      "a different proxy or Direct first, then disable it.")
    switched_off, switched_off_ids = [], []
    for r in config["rules"]:
        if r["action"] == name and r.get("enabled", True):
            r["enabled"] = False
            switched_off.append(rule_label(r))
            switched_off_ids.append(r["id"])
    # Devices pinned to it go back to following the rules, for the same reason.
    released = profile_devices(name, config)
    for mac in released:
        del config["device_policies"][mac]
    if switched_off or released:
        save_pattern_config(config)  # one firewall rebuild for all of it
    store["profiles"][name]["enabled"] = False
    # Remembered so re-enabling can offer to put exactly these back.
    store["profiles"][name]["disabled_with"] = {"rules": switched_off_ids, "devices": sorted(released)}
    save_store(store, apply_to_redsocks=False)
    message = f'Proxy profile "{name}" disabled: no health checks or email alerts for it.'
    if switched_off:
        message += (f" Also switched off {len(switched_off)} pattern rule{'s' if len(switched_off) != 1 else ''} "
                    f"that used it: {', '.join(switched_off)}.")
    if released:
        message += (f" {len(released)} device{'s' if len(released) != 1 else ''} that always used it now "
                    f"follow{'s' if len(released) == 1 else ''} the rules: {', '.join(released.values())}.")
    return message, None


def profile_devices(name, config):
    # {mac: label} of devices whose routing policy is this profile.
    store = load_devices_store()
    return {mac: device_label(store.get(mac, {}).get("nickname"), store.get(mac, {}).get("hostname"), mac=mac)
            for mac, action in config.get("device_policies", {}).items() if action == name}


def delete_proxy_profile(name):
    pattern_config = load_pattern_config()
    used_in = []
    if pattern_config["default_action"] == name:
        used_in.append("the Default Behaviour setting")
    for r in pattern_config["rules"]:
        if r["action"] == name:
            used_in.append(f'pattern rule "{rule_label(r)}"')
    for label in profile_devices(name, pattern_config).values():
        used_in.append(f'device "{label}" (Devices page)')
    if used_in:
        return (
            f'Cannot delete "{name}" — still used by: {", ".join(used_in)}. '
            "Change those to a different proxy or Direct first, then delete."
        )

    store = load_store()
    if name in store["profiles"]:
        del store["profiles"][name]
        save_store(store)
    return None


def format_uptime(seconds):
    if seconds is None:
        return "Unknown"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if days or hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


# (implementer, part) -> friendly name, decoded from ARM's registered ID
# values -- covers the Cortex-A cores found in Raspberry Pi boards and most
# other common ARM SBCs. Anything not listed here still shows its raw IDs
# rather than nothing.
_ARM_CPU_PARTS = {
    ("0x41", "0xb76"): "ARM1176 (ARMv6)",
    ("0x41", "0xc07"): "Cortex-A7",
    ("0x41", "0xc08"): "Cortex-A8",
    ("0x41", "0xc09"): "Cortex-A9",
    ("0x41", "0xd03"): "Cortex-A53",
    ("0x41", "0xd04"): "Cortex-A35",
    ("0x41", "0xd05"): "Cortex-A55",
    ("0x41", "0xd07"): "Cortex-A57",
    ("0x41", "0xd08"): "Cortex-A72",
    ("0x41", "0xd09"): "Cortex-A73",
    ("0x41", "0xd0a"): "Cortex-A75",
    ("0x41", "0xd0b"): "Cortex-A76",
}


def get_hardware_info():
    """Generic host hardware summary -- deliberately not Raspberry-Pi-specific,
    since this admin panel may end up running on different hardware later.
    Every field is gathered defensively; anything unavailable on a given
    host just falls back to "Unknown" rather than breaking the page.
    """
    # Board/hardware model: devicetree covers Raspberry Pi and most other
    # ARM SBCs, DMI covers most x86 PCs/servers -- try both, fall back to
    # "Unknown" rather than assuming either exists.
    model = None
    try:
        with open("/sys/firmware/devicetree/base/model", "rb") as f:
            model = f.read().split(b"\x00", 1)[0].decode(errors="replace").strip()
    except OSError:
        pass
    if not model:
        try:
            with open("/sys/class/dmi/id/sys_vendor") as f:
                vendor = f.read().strip()
            with open("/sys/class/dmi/id/product_name") as f:
                product = f.read().strip()
            model = f"{vendor} {product}".strip()
        except OSError:
            pass

    # x86 cpuinfo has a friendly "model name" line; ARM cpuinfo (e.g. every
    # Raspberry Pi) has neither that nor a useful "Hardware" line, only
    # numeric "CPU implementer"/"CPU part" IDs -- decode the common ones so
    # ARM boards don't just show "Unknown" for their CPU.
    cpu_model = None
    cpu_implementer = cpu_part = None
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                low = line.lower()
                if cpu_model is None and low.startswith(("model name", "hardware")):
                    cpu_model = line.split(":", 1)[1].strip()
                elif cpu_implementer is None and low.startswith("cpu implementer"):
                    cpu_implementer = line.split(":", 1)[1].strip().lower()
                elif cpu_part is None and low.startswith("cpu part"):
                    cpu_part = line.split(":", 1)[1].strip().lower()
    except OSError:
        pass
    if not cpu_model and cpu_implementer and cpu_part:
        cpu_model = _ARM_CPU_PARTS.get((cpu_implementer, cpu_part)) or (
            f"ARM CPU (implementer {cpu_implementer}, part {cpu_part})"
        )

    try:
        ram_total_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        # os.sysconf is POSIX-only; this is the deployment target (Linux),
        # but fail gracefully rather than crash the System page on any
        # other platform this code might ever run on for testing.
        ram_total_bytes = None

    try:
        disk = shutil.disk_usage("/")
        disk_total_bytes, disk_used_bytes = disk.total, disk.used
    except OSError:
        disk_total_bytes = disk_used_bytes = None

    try:
        os_pretty_name = platform.freedesktop_os_release().get("PRETTY_NAME", "Unknown")
    except OSError:
        os_pretty_name = "Unknown"

    cpu_temp_c = None
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            cpu_temp_c = int(f.read().strip()) / 1000.0
    except (OSError, ValueError):
        pass

    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        uptime_seconds = None

    return {
        "model": model or "Unknown",
        "architecture": platform.machine() or "Unknown",
        "cpu_model": cpu_model or platform.processor() or "Unknown",
        "cpu_cores": os.cpu_count() or "Unknown",
        "cpu_temp": f"{cpu_temp_c:.1f}°C" if cpu_temp_c is not None else None,
        "ram_total": format_bytes(ram_total_bytes),
        "disk_total": format_bytes(disk_total_bytes),
        "disk_used": format_bytes(disk_used_bytes),
        "disk_free": (
            format_bytes(disk_total_bytes - disk_used_bytes)
            if disk_total_bytes is not None and disk_used_bytes is not None
            else "Unknown"
        ),
        "os_pretty_name": os_pretty_name,
        "kernel": platform.release(),
        "hostname": platform.node(),
        "uptime": format_uptime(uptime_seconds),
    }


def get_ap_ssid():
    out = subprocess.run(
        ["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", AP_CONN_NAME],
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def get_wifi_band():
    # Prefer the live operating channel (real, from the radio itself) over
    # the connection's configured band, since it reflects reality even if
    # the config ever drifts -- but a disabled hotspot has no live channel
    # to report, so fall back to what's configured for that case.
    out = subprocess.run(["iw", "dev", AP_IFACE, "info"], capture_output=True, text=True)
    m = re.search(r"channel (\d+) \((\d+) MHz", out.stdout)
    if m:
        freq = int(m.group(2))
        return "5 GHz" if freq >= 3000 else "2.4 GHz"

    band = subprocess.run(
        ["nmcli", "-g", "802-11-wireless.band", "connection", "show", AP_CONN_NAME],
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {"a": "5 GHz", "bg": "2.4 GHz"}.get(band, "Unknown (hotspot not active)")


# Band/channel choices for the hotspot: value -> (nmcli band, channel, label).
# 5 GHz is limited to the non-DFS channels (36-48 and 149-165), the ones an
# access point can start on without radar detection. Not every country allows
# all of them, so the page only offers those the radio itself reports usable
# under its current regulatory domain (wifi_radio_choices()).
WIFI_RADIO_CHOICES = {"bg:0": ("bg", 0, "2.4 GHz, automatic channel")}
WIFI_RADIO_CHOICES.update({f"bg:{c}": ("bg", c, f"2.4 GHz, channel {c}") for c in (1, 6, 11)})
# 5 GHz "automatic" lets NetworkManager/the driver choose; if that lands on a
# channel the AP can't start on, set_wifi_radio() reverts as for any other choice.
WIFI_RADIO_CHOICES["a:0"] = ("a", 0, "5 GHz, automatic channel")
WIFI_RADIO_CHOICES.update({f"a:{c}": ("a", c, f"5 GHz, channel {c}") for c in (36, 40, 44, 48, 149, 153, 157, 161, 165)})


# `iw list` channel flags that mean an access point can't start there.
_AP_UNUSABLE_FLAGS = ("disabled", "no IR", "no-IR", "radar detection", "passive scan")


def usable_wifi_channels():
    """Channels the radio may start an access point on under its current
    regulatory domain, from `iw list`; None if that can't be read."""
    try:
        out = subprocess.run(["iw", "list"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    usable = set()
    for m in re.finditer(r"\*\s+[\d.]+ MHz \[(\d+)\](.*)", out or ""):
        if not any(flag in m.group(2) for flag in _AP_UNUSABLE_FLAGS):
            usable.add(int(m.group(1)))
    return usable or None


def wifi_radio_choices(current=None):
    """WIFI_RADIO_CHOICES narrowed to what this radio may use here. Fails
    open to the full list (set_wifi_radio() reverts a choice that won't
    start anyway), and always keeps the current setting so it stays shown."""
    usable = usable_wifi_channels()
    if usable is None:
        return WIFI_RADIO_CHOICES
    has_5ghz = any(c > 14 for c in usable)
    return {key: choice for key, choice in WIFI_RADIO_CHOICES.items()
            if key == current
            or choice[1] in usable
            or (choice[1] == 0 and (choice[0] == "bg" or has_5ghz))}


def get_wifi_radio():
    # The hotspot's configured band/channel, as a WIFI_RADIO_CHOICES key.
    out = subprocess.run(
        ["nmcli", "-g", "802-11-wireless.band,802-11-wireless.channel", "connection", "show", AP_CONN_NAME],
        capture_output=True, text=True,
    ).stdout.strip().splitlines()
    band = out[0].strip() if out else "bg"
    channel = out[1].strip() if len(out) > 1 else "0"
    key = f"{band or 'bg'}:{channel or '0'}"
    return key if key in WIFI_RADIO_CHOICES else "bg:0"


def live_wifi_frequency():
    out = subprocess.run(["iw", "dev", AP_IFACE, "info"], capture_output=True, text=True)
    m = re.search(r"channel (\d+) \((\d+) MHz", out.stdout)
    return (int(m.group(1)), int(m.group(2))) if m else (None, None)


def set_wifi_radio(choice):
    """Moves the hotspot to another band/channel. Returns (message, error).
    If it doesn't come back up on the requested band, the previous setting is
    restored, so a choice the radio rejects can't leave the box without Wi-Fi."""
    if choice not in WIFI_RADIO_CHOICES:
        return None, "Unknown band/channel"
    old = get_wifi_radio()
    if choice == old:
        return "Nothing to change.", None

    def apply(key):
        band, channel, _ = WIFI_RADIO_CHOICES[key]
        # "Automatic" is an empty channel: nmcli rejects 0 ("not a valid
        # channel"), found live 2026-10-01 moving back from 5 GHz.
        subprocess.run(["sudo", "-n", "/usr/bin/nmcli", "connection", "modify", AP_CONN_NAME,
                        "802-11-wireless.band", band, "802-11-wireless.channel", str(channel) if channel else ""],
                       check=True, capture_output=True)

    was_active = get_hotspot_enabled()
    try:
        apply(choice)
    except subprocess.CalledProcessError:
        return None, f"NetworkManager refused {WIFI_RADIO_CHOICES[choice][2]}; nothing was changed."
    label = WIFI_RADIO_CHOICES[choice][2]
    if not was_active:
        return f"Saved: {label}. The hotspot is disabled, so it takes effect when you enable it.", None
    try:
        subprocess.run(["sudo", "-n", "/usr/bin/nmcli", "connection", "up", AP_CONN_NAME],
                       check=True, capture_output=True, timeout=60)
        time.sleep(2)
        _, freq = live_wifi_frequency()
        want_5 = WIFI_RADIO_CHOICES[choice][0] == "a"
        if freq is None or (freq >= 3000) != want_5:
            raise RuntimeError("the radio didn't start on that band")
    except Exception:
        apply(old)
        try:
            subprocess.run(["sudo", "-n", "/usr/bin/nmcli", "connection", "up", AP_CONN_NAME],
                           check=True, capture_output=True, timeout=60)
        except Exception:
            pass
        return None, (f"The hotspot couldn't start on {label}, so it's back on "
                      f"{WIFI_RADIO_CHOICES[old][2]}. Nothing else changed.")
    channel, freq = live_wifi_frequency()
    return (f"The hotspot is now on {label} (live: channel {channel}, {freq} MHz). Devices reconnect by "
            "themselves; any that only support 2.4 GHz can no longer see it." if WIFI_RADIO_CHOICES[choice][0] == "a"
            else f"The hotspot is now on {label} (live: channel {channel})."), None


def wifi_qr_payload(ssid, passphrase):
    # The standard "join this Wi-Fi" QR text phone cameras understand.
    def esc(value):
        return re.sub(r'([\\;,:"])', r"\\\1", value)
    return f"WIFI:T:WPA;S:{esc(ssid)};P:{esc(passphrase)};;"


def get_wifi_qr_svg():
    """SVG QR code that joins the hotspot, or None if python3-qrcode isn't
    installed. The passphrase is read from NetworkManager's secret store
    (root-only, hence the narrow sudo rule), kept in memory only long enough
    to draw the code, and never logged or saved."""
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None
    out = subprocess.run(
        ["sudo", "-n", "/usr/bin/nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", AP_CONN_NAME],
        capture_output=True, text=True, timeout=10,
    )
    passphrase = out.stdout.strip()
    if out.returncode != 0 or not passphrase:
        raise RuntimeError("Couldn't read the hotspot's passphrase")
    image = qrcode.make(wifi_qr_payload(get_ap_ssid(), passphrase), image_factory=qrcode.image.svg.SvgPathImage,
                        box_size=8, border=2)
    del passphrase
    return image.to_string(encoding="unicode")


def set_ap_wifi(ssid, passphrase):
    # Preserve the current enabled/disabled state: a deliberately-disabled
    # hotspot shouldn't silently come back just because its SSID/passphrase
    # were edited, and this same function backs the "Restart Wi-Fi" button
    # (called with empty ssid/passphrase), which is a no-op while disabled.
    was_enabled = get_hotspot_enabled()
    if ssid:
        subprocess.run(
            [
                "sudo",
                "-n",
                "/usr/bin/nmcli",
                "connection",
                "modify",
                AP_CONN_NAME,
                "802-11-wireless.ssid",
                ssid,
            ],
            check=True,
        )
    if passphrase:
        subprocess.run(
            [
                "sudo",
                "-n",
                "/usr/bin/nmcli",
                "connection",
                "modify",
                AP_CONN_NAME,
                "wifi-sec.psk",
                passphrase,
            ],
            check=True,
        )
    if was_enabled:
        subprocess.run(["sudo", "-n", "/usr/bin/nmcli", "connection", "up", AP_CONN_NAME], check=True)


def get_hotspot_enabled():
    out = subprocess.run(
        ["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"],
        capture_output=True,
        text=True,
    )
    return AP_CONN_NAME in out.stdout.splitlines()


def set_hotspot_enabled(enabled):
    autoconnect = "yes" if enabled else "no"
    subprocess.run(
        ["sudo", "-n", "/usr/bin/nmcli", "connection", "modify", AP_CONN_NAME, "connection.autoconnect", autoconnect],
        check=True,
    )
    if enabled:
        subprocess.run(["sudo", "-n", "/usr/bin/nmcli", "connection", "up", AP_CONN_NAME], check=True)
    else:
        subprocess.run(["sudo", "-n", "/usr/bin/nmcli", "connection", "down", AP_CONN_NAME], check=True)


def reboot_system():
    # Scheduled a few seconds out via a transient systemd timer, rather than
    # rebooting inline, so this request can actually finish and the browser
    # gets a response before the box goes down.
    subprocess.run(
        ["sudo", "-n", "/usr/bin/systemd-run", "--on-active=3", "/usr/sbin/reboot"],
        check=True,
    )


def signal_quality(dbm):
    # Rough RSSI bands commonly used for Wi-Fi: returns (bars 0-4, label).
    if dbm is None:
        return 0, ""
    if dbm >= -50:
        return 4, "Excellent"
    if dbm >= -60:
        return 3, "Good"
    if dbm >= -70:
        return 2, "Fair"
    return 1, "Weak"


def get_station_dump():
    # Per-station live radio data straight from the AP (no sudo needed):
    # connected time, and signal strength as heard by the AP. "signal avg"
    # is preferred over the instantaneous "signal" when the driver reports
    # it, since it's much less jumpy between refreshes.
    stations = {}
    out = subprocess.run(
        ["iw", "dev", AP_IFACE, "station", "dump"], capture_output=True, text=True
    )
    mac = None
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("Station "):
            mac = line.split()[1].lower()
            stations[mac] = {"connected_time": "", "signal_dbm": None, "_signal_now": None}
        elif mac and line.startswith("connected time:"):
            stations[mac]["connected_time"] = line.split(":", 1)[1].strip()
        elif mac and (line.startswith("signal avg:") or line.startswith("signal:")):
            m = re.match(r"-?\d+", line.split(":", 1)[1].strip())
            if m:
                key = "signal_dbm" if line.startswith("signal avg:") else "_signal_now"
                stations[mac][key] = int(m.group())
    for s in stations.values():
        now = s.pop("_signal_now")
        if s["signal_dbm"] is None:
            s["signal_dbm"] = now
        s["signal_bars"], s["signal_label"] = signal_quality(s["signal_dbm"])
    return stations


def get_lease_map():
    # DHCP leases handed out by the hotspot: ip -> (mac, hostname).
    leases = subprocess.run(
        ["sudo", "-n", "/bin/cat", LEASE_FILE], capture_output=True, text=True
    )
    result = {}
    for line in leases.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            result[parts[2]] = (parts[1].lower(), "" if parts[3] == "*" else parts[3])
    return result


def get_connected_devices():
    stations = {}
    for mac, s in get_station_dump().items():
        stations[mac] = {"mac": mac, "ip": "", "hostname": "", **s}

    for ip, (lease_mac, hostname) in get_lease_map().items():
        if lease_mac in stations:
            stations[lease_mac]["ip"] = ip
            stations[lease_mac]["hostname"] = hostname

    return sorted(stations.values(), key=lambda d: d["ip"] or d["mac"])


def load_devices_store():
    try:
        with open(DEVICES_STORE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_devices_store(store):
    os.makedirs(os.path.dirname(DEVICES_STORE), exist_ok=True)
    with open(DEVICES_STORE, "w") as f:
        json.dump(store, f, indent=2)
    os.chmod(DEVICES_STORE, 0o660)


def get_all_devices(live_devices):
    # Merges live association/lease data into the persistent known-devices
    # store (so history and blocked state survive a device going offline —
    # blocking would otherwise make it vanish from view entirely, with no
    # way to unblock it again), then returns every known device, live ones
    # first, each carrying its live state where currently connected.
    store = load_devices_store()
    now = datetime.now(timezone.utc).isoformat()
    for d in live_devices:
        entry = store.setdefault(d["mac"], {"mac": d["mac"], "first_seen": now, "blocked": False})
        entry["last_seen"] = now
        if d["hostname"]:
            entry["hostname"] = d["hostname"]
    save_devices_store(store)

    live_by_mac = {d["mac"]: d for d in live_devices}
    result = []
    for mac, entry in store.items():
        live = live_by_mac.get(mac)
        result.append(
            {
                "mac": mac,
                "hostname": (live["hostname"] if live and live["hostname"] else entry.get("hostname", "")),
                "ip": live["ip"] if live else "",
                "connected_time": live["connected_time"] if live else "",
                "signal_dbm": live["signal_dbm"] if live else None,
                "signal_bars": live["signal_bars"] if live else 0,
                "signal_label": live["signal_label"] if live else "",
                "online": live is not None,
                "blocked": entry.get("blocked", False),
                "nickname": entry.get("nickname", ""),
            }
        )
    result.sort(key=lambda d: (not d["online"], d["ip"] or "", d["mac"]))
    return result


def device_label(nickname, hostname, ip="", mac=""):
    # How a device is named everywhere: its nickname, else its hostname, else
    # its address; with the IP alongside where that helps tell devices apart.
    name = nickname or hostname
    if name and ip:
        return f"{name} ({ip})"
    return name or ip or mac


def set_device_nickname(mac, nickname):
    nickname = " ".join((nickname or "").split())[:NICKNAME_MAX]
    store = load_devices_store()
    if mac not in store:
        return False
    if nickname:
        store[mac]["nickname"] = nickname
    else:
        store[mac].pop("nickname", None)
    save_devices_store(store)
    return True


def set_device_policy(mac, action):
    """Returns (message, error). action: "" (follow the rules), "direct", or
    a proxy profile name. Lives in pattern_rules.json, not devices.json, so
    the firewall can still be rebuilt from that one file at boot."""
    if mac not in load_devices_store():
        return None, "Unknown device"
    profiles = load_store()["profiles"]
    if action not in ("", "direct") and action not in profiles:
        return None, "Unknown routing choice"
    if action in profiles and not profiles[action].get("enabled", True):
        return None, f'"{action}" is disabled. Enable it on the Proxy Profiles page first.'
    config = load_pattern_config()
    if action:
        config["device_policies"][mac] = action
    else:
        config["device_policies"].pop(mac, None)
    save_pattern_config(config)  # rebuilds the firewall
    if not action:
        return "This device now follows the rules again.", None
    where = "direct, ignoring the rules" if action == "direct" else f'through "{action}", ignoring the rules'
    return f"This device's traffic now always goes {where}.", None


def apply_device_denylist(store):
    denylist = ",".join(mac for mac, d in store.items() if d.get("blocked"))
    subprocess.run(
        [
            "sudo",
            "-n",
            "/usr/bin/nmcli",
            "connection",
            "modify",
            AP_CONN_NAME,
            "802-11-wireless.mac-address-denylist",
            denylist,
        ],
        check=True,
    )
    # Reactivating is the only reliable way to also drop a device that's
    # already associated, or to make an unblock take effect immediately —
    # NetworkManager applies this list when the connection (re)activates,
    # the same reason set_ap_wifi() re-activates after an SSID/PSK change.
    if get_hotspot_enabled():
        subprocess.run(["sudo", "-n", "/usr/bin/nmcli", "connection", "up", AP_CONN_NAME], check=True)


def block_device(mac):
    store = load_devices_store()
    if mac not in store:
        return False
    store[mac]["blocked"] = True
    save_devices_store(store)
    apply_device_denylist(store)
    return True


def unblock_device(mac):
    store = load_devices_store()
    if mac not in store:
        return False
    store[mac]["blocked"] = False
    save_devices_store(store)
    apply_device_denylist(store)
    return True


def sync_traffic_accounting(devices):
    ips = [d["ip"] for d in devices if d["ip"]]
    subprocess.run(["sudo", "-n", TRAFFIC_SYNC_HELPER, AP_IFACE, *ips], check=True)


def _parse_traffic_chain(chain):
    out = subprocess.run(
        ["sudo", "-n", "/usr/sbin/iptables", "-t", "mangle", "-L", chain, "-n", "-v", "-x"],
        capture_output=True,
        text=True,
    )
    counts = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) < 9 or not parts[0].isdigit():
            continue
        pkt_bytes = int(parts[1])
        source, dest = parts[7], parts[8]
        ip = source if source != "0.0.0.0/0" else dest
        ip = ip.split("/")[0]
        counts[ip] = pkt_bytes
    return counts


def read_traffic_counters():
    up = _parse_traffic_chain("WPXACCT_UP")
    down = _parse_traffic_chain("WPXACCT_DOWN")
    return {ip: {"up": up.get(ip, 0), "down": down.get(ip, 0)} for ip in set(up) | set(down)}


def format_bytes(n):
    if n is None:
        return "Unknown"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def load_pattern_config():
    # bypass_cidr/default_action/rule "action" values are trusted as stored;
    # the template shows "(missing)" and the firewall helper fails open to
    # direct if a referenced profile no longer exists. Storing bypass_cidr
    # here, rather than recovering it by parsing live iptables output, is
    # what lets the whole chain be rebuilt from scratch on every boot —
    # ipset contents are never persisted across a reboot by netfilter-
    # persistent, so re-deriving state from a snapshot of the (possibly
    # already-broken) live rules doesn't work as a recovery path.
    try:
        with open(PATTERN_RULES_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    rules = data.get("rules", [])
    for r in rules:
        r.setdefault("enabled", True)
    return {
        "bypass_cidr": data.get("bypass_cidr", ""),
        "default_action": data.get("default_action", "direct"),
        "rules": rules,
        # Read by dns_router.py: look up proxied rules' hostnames through the
        # proxy (see proxy_doh.py). Must round-trip here, or any save drops it.
        "resolve_via_proxy": bool(data.get("resolve_via_proxy", True)),
        # Read by the firewall helper and dns_router.py (see LEAK_GUARDS).
        "leak_guards": {k: bool((data.get("leak_guards") or {}).get(k, True)) for k in LEAK_GUARDS},
        # Per-device routing (Devices page), read by the firewall helper:
        # MAC -> "direct" or a profile name; absent means "follow the rules".
        "device_policies": {mac.lower(): action for mac, action in (data.get("device_policies") or {}).items()
                            if isinstance(mac, str) and MAC_RE.fullmatch(mac.lower()) and isinstance(action, str)},
    }


def save_pattern_config(config):
    os.makedirs(os.path.dirname(PATTERN_RULES_FILE), exist_ok=True)
    with open(PATTERN_RULES_FILE, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(PATTERN_RULES_FILE, 0o640)
    rebuild_firewall()


def get_bypass_cidr():
    return load_pattern_config()["bypass_cidr"]


def rebuild_firewall():
    subprocess.run(["sudo", "-n", REBUILD_FIREWALL_HELPER, AP_IFACE], check=True)


def set_bypass_cidr(cidr):
    config = load_pattern_config()
    config["bypass_cidr"] = cidr
    save_pattern_config(config)


def load_pattern_rules():
    return load_pattern_config()["rules"]


def get_default_action():
    return load_pattern_config()["default_action"]


def set_default_action(action):
    config = load_pattern_config()
    config["default_action"] = action
    save_pattern_config(config)


def rule_label(rule, limit=60):
    # How a rule is named in messages and lists: its description, else its patterns.
    label = rule.get("description") or ", ".join(rule_patterns(rule))
    return label if len(label) <= limit else label[:limit - 1] + "…"


def upsert_pattern_rule(rule_id, patterns, mode, action, description):
    if isinstance(patterns, str):
        patterns = [patterns]
    # "pattern" (the first one) is still written for anything that predates
    # multi-pattern rules, e.g. a rolled-back dns_router.py.
    fields = dict(patterns=list(patterns), pattern=patterns[0], mode=mode, action=action, description=description)
    config = load_pattern_config()
    rules = config["rules"]
    if rule_id:
        for r in rules:
            if r["id"] == rule_id:
                old = rule_patterns(r)
                if r["mode"] != mode or not set(old) <= set(patterns):
                    # A rule's ipset (wpx_<id>) holds every IP its old patterns
                    # matched, for up to 24h. Removing a pattern (or changing
                    # the mode) would leave those IPs routed by this rule, so it
                    # gets a fresh, empty set (the rebuild prunes the old one).
                    # Only *adding* patterns keeps the set: its IPs are all still wanted.
                    r["id"] = uuid.uuid4().hex[:8]
                r.update(fields)
                break
        else:
            return False
    else:
        rules.append(dict(fields, id=uuid.uuid4().hex[:8], enabled=True))
    save_pattern_config(config)
    return True


def parse_patterns(text):
    # The form's "one per line" box -> a clean, de-duplicated list. Commas work too.
    seen, out = set(), []
    for p in re.split(r"[\r\n,]+", text or ""):
        p = p.strip()
        if p and p.lower() not in seen:
            seen.add(p.lower())
            out.append(p)
    return out


def patterns_problem(patterns, mode):
    if not patterns:
        return "At least one pattern is required."
    if len(patterns) > MAX_PATTERNS_PER_RULE:
        return f"At most {MAX_PATTERNS_PER_RULE} patterns per rule."
    problems = [pattern_problem(p, mode) for p in patterns]
    problems = [p for p in problems if p]
    return " ".join(problems) if problems else None


def toggle_pattern_rule(rule_id):
    config = load_pattern_config()
    for r in config["rules"]:
        if r["id"] == rule_id:
            r["enabled"] = not r.get("enabled", True)
            break
    else:
        return False
    save_pattern_config(config)
    return True


def delete_pattern_rule(rule_id):
    config = load_pattern_config()
    config["rules"] = [r for r in config["rules"] if r["id"] != rule_id]
    save_pattern_config(config)


def move_pattern_rule(rule_id, direction):
    config = load_pattern_config()
    rules = config["rules"]
    idx = next((i for i, r in enumerate(rules) if r["id"] == rule_id), None)
    if idx is None:
        return
    new_idx = idx - 1 if direction == "up" else idx + 1
    if 0 <= new_idx < len(rules):
        rules[idx], rules[new_idx] = rules[new_idx], rules[idx]
        save_pattern_config(config)


def registrable_domain(name):
    labels = name.split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL_LABELS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def suggest_rule_pattern(name):
    # What the DNS Lookups page's "Add rule" pre-fills for a looked-up name:
    # a wildcard over the whole site (e.g. *.netrw.it for
    # raicinque1-push.cdn.netrw.it), except under a shared CDN, where it's
    # the exact hostname only.
    base = registrable_domain(name)
    if base == name or base in SHARED_CDN_DOMAINS:
        return name, "match"
    return f"*.{base}", "wildcard"


def pattern_for_mode(name, mode):
    # The pattern "Add to rule" appends for a looked-up name, in the target
    # rule's own mode: one rule has one mode for all its patterns.
    if mode == "match":
        return name
    if mode == "regexp":
        return name.replace(".", r"\.")  # HOSTNAME_RE leaves "." as the only special character
    return suggest_rule_pattern(name)[0]


def get_rule_addition(args, rules):
    # "Add to rule" from the DNS Lookups page: opens that rule's Edit form
    # with one more pattern for the host. Like get_rule_prefill, nothing is
    # saved here; the admin reviews and submits the normal form.
    host = args.get("add_host", "").strip().lower()
    index, rule = next(((i, r) for i, r in enumerate(rules) if r["id"] == args.get("edit_pattern")), (None, None))
    if rule is None or not host or len(host) > 253 or not HOSTNAME_RE.fullmatch(host):
        return None
    pattern = pattern_for_mode(host, rule["mode"])
    prepared = prepare_rule(rule)
    earlier = next((r for r in rules[:index] if r.get("enabled", True)
                    and (p := prepare_rule(r)) and matching_pattern(host, p) is not None), None)
    return {
        "host": host,
        "pattern": pattern,
        "already": pattern in rule_patterns(rule) or bool(prepared and matching_pattern(host, prepared) is not None),
        "shadowed_by": rule_label(earlier) if earlier else "",
        "rule_off": not rule.get("enabled", True),
    }


WILDCARD_PATTERN_RE = re.compile(r"[a-z0-9.*?\[\]!_-]+")


def pattern_problem(pattern, mode):
    # Why a rule could never match anything, or None. Rules match the
    # *hostname* a device looks up (dns_router.py sees nothing else), so a
    # URL, path or port can never match -- e.g. the "*.discoveryplus.com/*"
    # rule found on the box on 2026-09-30, which had silently never matched.
    if not pattern or len(pattern) > 253:
        return "A pattern is required (at most 253 characters)."
    if mode == "regexp":
        try:
            re.compile(pattern)
        except re.error as e:
            return f"Invalid regular expression: {e}"
        return None
    p = pattern.lower()
    if "://" in p or "/" in p:
        host = p.split("://", 1)[-1].split("/", 1)[0]
        return (f'"{pattern}" can never match: rules match hostnames only, never URLs or paths. '
                f'Use just the hostname part, e.g. "{host}".')
    if ":" in p:
        return f'"{pattern}" can never match: hostnames don\'t include a port number.'
    if not WILDCARD_PATTERN_RE.fullmatch(p):
        return ("Patterns can only contain letters, digits, dots, hyphens and the wildcards * ? [ ] "
                "(no spaces).")
    if mode == "match" and any(c in p for c in "*?["):
        return f'"{pattern}" has a wildcard but the mode is Exact match. Choose Wildcard instead.'
    if p.startswith(".") or p.endswith(".") or ".." in p:
        return f'"{pattern}" can never match: it has an empty part between dots.'
    return None


def rule_notes(patterns, mode, action):
    # Extra heads-ups appended to "rule saved"-type messages.
    if isinstance(patterns, str):
        patterns = [patterns]
    notes = ""
    for pattern in patterns:
        base = pattern.lower().lstrip("*.?")
        if mode == "wildcard" and pattern.startswith("*") and base in SHARED_CDN_DOMAINS:
            notes += (f" Heads-up: {base} is a shared CDN used by thousands of unrelated sites, so "
                      f'"{pattern}" will send far more than one service through this rule\'s action. '
                      "A more specific pattern or an exact hostname is usually better.")
    profile = load_store()["profiles"].get(action)
    if profile and not profile.get("enabled", True):
        notes += f' Note: its proxy profile "{action}" is disabled, so it isn\'t health-checked.'
    return notes


def action_label(action, profiles):
    if action == "direct":
        return "Direct"
    return action if action in profiles else f"{action} (missing)"


def read_lookups_snapshot():
    try:
        with open(LOOKUPS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def get_health_view():
    now = time.time()
    try:
        with open(HEALTH_STATUS_FILE) as f:
            status = json.load(f)
    except (OSError, ValueError):
        return {"now": now, "state": "unavailable", "overall": "unknown", "checks": [], "alerts": {},
                "message": "No health data yet. The first check runs about 90 seconds after boot, "
                           "then every 2 minutes (is rasp-proxy-health.timer enabled?)."}
    stale = now - status.get("generated", 0) > HEALTH_STALE_SECONDS
    for c in status.get("checks", []):
        c.pop("alert", None)
    return {
        "now": now,
        "state": "stale" if stale else "ok",
        "message": "Health checks have stopped running: this data is out of date (is rasp-proxy-health.timer enabled?)." if stale else "",
        "generated": status.get("generated"),
        "overall": status.get("overall", "unknown"),
        "checks": status.get("checks", []),
        "alerts": status.get("alerts", {}),
    }


def run_health_check_now():
    # --no-block: returns straight away; the Overview page polls for the result.
    subprocess.run(
        ["sudo", "-n", "/usr/bin/systemctl", "start", "--no-block", "rasp-proxy-health.service"],
        check=True, capture_output=True, timeout=10,
    )


def parse_alerts_form(form, current):
    # Returns (config, error). A blank password keeps the saved one.
    host = form.get("smtp_host", "").strip()
    port = form.get("smtp_port", "").strip() or "587"
    security = form.get("security", "starttls")
    recipients = form.get("recipients", "").strip()
    sender = form.get("sender", "").strip()
    if host and not SMTP_HOST_RE.fullmatch(host):
        return None, "Invalid SMTP server name"
    if not port.isdigit() or not 0 < int(port) < 65536:
        return None, "Invalid SMTP port"
    if security not in ("starttls", "ssl", "none"):
        return None, "Invalid connection security"
    bad = [r for r in re.split(r"[,;]", recipients) if r.strip() and not EMAIL_RE.fullmatch(r.strip())]
    if bad:
        return None, f"Invalid recipient address: {bad[0].strip()[:60]}"
    if sender and not EMAIL_RE.fullmatch(sender):
        return None, "Invalid sender address"
    limits = {}
    for key, what in (("recover_after_min", "Recovered after"), ("min_interval_min", "At most one email every")):
        raw = str(form.get(key, current.get(key, _MAILER_DEFAULTS[key]))).strip()
        if not raw.isdigit() or int(raw) > _MAILER_LIMITS[key]:
            return None, f"{what}: enter a number of minutes from 0 to {_MAILER_LIMITS[key]}"
        limits[key] = int(raw)
    config = dict(current)
    config.update(
        enabled=form.get("enabled") == "1",
        smtp_host=host,
        smtp_port=int(port),
        security=security,
        username=form.get("username", "").strip()[:200],
        sender=sender,
        recipients=recipients[:500],
        notify_boot=form.get("notify_boot") == "1",
        **limits,
    )
    if form.get("password"):
        config["password"] = form["password"]
    if config["enabled"] and not (host and recipients):
        return None, "To turn alerts on, fill in at least the SMTP server and one recipient."
    return config, None


def explain_hostname(raw):
    """The rule tester: exactly what this box would do with a hostname, using
    the same matcher as dns_router.py. Accepts a pasted URL too."""
    host = (raw or "").strip().lower()
    host = host.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    if not HOSTNAME_RE.fullmatch(host) or len(host) > 253:
        return {"ok": False, "error": "Type a hostname such as www.raiplay.it (a full URL works too)."}
    config = load_pattern_config()
    profiles = load_store()["profiles"]
    winner, shadowed, disabled = None, [], []
    for index, r in enumerate(config["rules"], 1):
        prepared = prepare_rule(r)
        pattern = matching_pattern(host, prepared) if prepared else None
        if pattern is None:
            continue
        entry = {"index": index, "id": r["id"], "label": rule_label(r), "pattern": pattern,
                 "action": action_label(r["action"], profiles)}
        if not r.get("enabled", True):
            disabled.append(entry)
        elif winner is None:
            winner = dict(entry, raw_action=r["action"])
        else:
            shadowed.append(entry)
    action = winner["raw_action"] if winner else config["default_action"]
    proxied = action != "direct" and action in profiles
    via_proxy_dns = bool(winner and proxied and config.get("resolve_via_proxy", True))
    notes = []
    if proxied:
        notes.append("QUIC (HTTP/3) to it is blocked, so apps fall back to TCP, which goes through the proxy.")
        if not profiles[action].get("enabled", True):
            notes.append(f'Its proxy profile "{action}" is disabled, so it isn\'t health-checked.')
    elif action != "direct":
        notes.append(f'The action "{action}" names a profile that no longer exists, so it goes direct.')
    pinned = config.get("device_policies") or {}
    if pinned:
        known = load_devices_store()
        names = [device_label(known.get(mac, {}).get("nickname"), known.get(mac, {}).get("hostname"), mac=mac)
                 for mac in pinned]
        notes.append(f"Except on {len(names)} device{'s' if len(names) != 1 else ''} with their own routing "
                     f"setting (Devices page), which ignore the rules: {', '.join(names)}.")
    return {
        "ok": True,
        "host": host,
        "rule": winner and {k: v for k, v in winner.items() if k != "raw_action"},
        "shadowed": shadowed,
        "disabled": disabled,
        "route": action_label(action, profiles) if action in profiles or action == "direct" else "Direct",
        "proxied": proxied,
        "decided_by": f"rule #{winner['index']}" if winner else "the Default Behaviour",
        "dns": ("looked up through the proxy (Proxied Lookups)" if via_proxy_dns
                else "looked up with ordinary DNS"),
        "notes": notes,
    }


def get_rule_activity(pattern_rules, lookups_snapshot, health_status):
    """Per-rule activity for the rules table: recent lookups (from the DNS
    Lookups capture, so dnsmasq cache hits count too, matched against the
    rules as they are now) and connections the firewall redirected since the
    chain was last rebuilt (from the health check, which can read iptables
    counters as root)."""
    rules = [(r["id"], p) for r in pattern_rules if r.get("enabled", True) for p in [prepare_rule(r)] if p]
    activity = {r["id"]: {"lookups": 0, "last": 0, "last_name": "", "connections": None} for r in pattern_rules}
    names = {}
    for entries in (lookups_snapshot or {}).get("clients", {}).values():
        for e in entries:
            name = e.get("name", "")
            if HOSTNAME_RE.fullmatch(name):
                n = names.setdefault(name, {"count": 0, "last": 0})
                n["count"] += e.get("count", 0)
                n["last"] = max(n["last"], e.get("last", 0))
    for name, n in names.items():
        for rule_id, prepared in rules:
            if matching_pattern(name, prepared) is not None:
                a = activity[rule_id]
                a["lookups"] += n["count"]
                if n["last"] > a["last"]:
                    a["last"], a["last_name"] = n["last"], name
                break
    for rule_id, packets in ((health_status or {}).get("rule_connections") or {}).items():
        if rule_id in activity:
            activity[rule_id]["connections"] = packets
    return activity


def ago(timestamp, now=None):
    seconds = max(0, int((now or time.time()) - timestamp))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def read_health_status():
    try:
        with open(HEALTH_STATUS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def get_lookups_view():
    # Each looked-up name's route is evaluated against the rules as they are
    # *now*, not as they were at lookup time: new connections follow the
    # current rules (see the ~1 minute note in HELP_PATTERN_RULES), and it
    # means a rule just added from this page shows up here straight away.
    now = time.time()
    view = {"now": now, "status": "ok", "message": "", "clients": [], "entries": [], "rules": []}
    snapshot = read_lookups_snapshot()
    if snapshot is None:
        view.update(status="unavailable", message="No lookup data yet. The DNS router hasn't written any (is rasp-proxy-dns-router running?).")
        return view
    if snapshot.get("capture") not in (None, "ok"):
        view.update(status="error", message=f"Lookup capture problem: {snapshot['capture']}")
    elif now - snapshot.get("generated", 0) > LOOKUPS_STALE_SECONDS:
        view.update(status="stale", message="The DNS router has stopped updating lookups (is rasp-proxy-dns-router running?). Showing the last data it wrote.")

    config = load_pattern_config()
    # Capture sees queries as sent, before the DNS leak guard redirects them,
    # so with the guard on an "asked 8.8.8.8" lookup was still answered here.
    view["dns_guard"] = config.get("leak_guards", {}).get("dns", True)
    profiles = load_store()["profiles"]
    rules = [p for p in (prepare_rule(r) for r in config["rules"] if r.get("enabled", True)) if p]
    default_action = config["default_action"]
    first_profile = next(iter(profiles), None)
    # For each row's "Add to rule" picker, in table order.
    view["rules"] = [{"id": r["id"],
                      "label": f"#{i} {rule_label(r, 40)} → {action_label(r['action'], profiles)}"
                               + ("" if r.get("enabled", True) else " (off)")}
                     for i, r in enumerate(config["rules"], 1)]
    leases = get_lease_map()
    known = load_devices_store()

    for ip, names in snapshot.get("clients", {}).items():
        mac, hostname = leases.get(ip, ("", ""))
        entry = known.get(mac, {})
        label = device_label(entry.get("nickname"), hostname or entry.get("hostname", ""), ip)
        policy = config.get("device_policies", {}).get(mac)  # overrides every rule for this device
        names = [e for e in names if HOSTNAME_RE.fullmatch(e.get("name", ""))]
        view["clients"].append({"ip": ip, "label": label, "last": max((e.get("last", 0) for e in names), default=0)})
        for e in names:
            name = e["name"]
            rule = None if policy else match_rule(name, rules)
            action = policy or (rule["action"] if rule else default_action)
            proxied = action != "direct" and action in profiles
            pattern, mode = suggest_rule_pattern(name)
            view["entries"].append({
                "ip": ip,
                "device": label,
                "name": name,
                "last": e.get("last", 0),
                "count": e.get("count", 0),
                "bypass": [b for b in e.get("bypass", []) if isinstance(b, str) and re.fullmatch(r"[0-9.]{7,15}", b)],
                "proxied": proxied,
                "action": action_label(action, profiles),
                "via": "device setting" if policy else (f"rule {matching_pattern(name, rule)}" if rule else "default"),
                "rule_id": rule["id"] if rule else "",
                "rule_label": rule_label(rule, 40) if rule else "",
                # Pre-selects the opposite of the current route: a name going
                # direct is usually being looked at because it should be proxied.
                "suggest": {"pattern": pattern, "mode": mode,
                            "action": "direct" if proxied or not first_profile else first_profile},
            })
    view["clients"].sort(key=lambda c: -c["last"])
    view["entries"].sort(key=lambda e: -e["last"])
    return view


REQUIRED_PROFILE_FIELDS = {"description", "type", "ip", "port", "login", "password", "local_port"}
REQUIRED_RULE_FIELDS = {"id", "pattern", "mode", "action", "description"}


def mailer_defaults():
    return dict(_MAILER_DEFAULTS)


def export_config():
    # Includes upstream proxy credentials and the SMTP password in plain text,
    # by necessity (a restorable backup has to carry them) -- the file this
    # produces is as sensitive as /etc/redsocks.conf itself and should be
    # stored accordingly. Wi-Fi SSID/passphrase are deliberately not included:
    # restoring Wi-Fi settings has a much bigger blast radius (every connected
    # device would need to rejoin) than restoring proxy/rule data.
    # "patterns" carries the rules plus the default, Proxied Lookups, the leak
    # guards and per-device routing.
    devices = {mac: {k: d[k] for k in ("nickname", "blocked") if d.get(k)}
               for mac, d in load_devices_store().items() if d.get("nickname") or d.get("blocked")}
    return {
        "format": 2,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "bypass_cidr": get_bypass_cidr(),
        "proxies": load_store(),
        "patterns": load_pattern_config(),
        "alerts": load_alerts_config(),
        "devices": devices,
    }


def import_config(data):
    # Returns an error string, or None on success. Deliberately conservative:
    # rejects anything that doesn't look like our own export rather than
    # trying to guess intent from a partially-malformed file.
    if not isinstance(data, dict):
        return "Invalid file: not a JSON object"

    bypass_cidr = data.get("bypass_cidr", "")
    if not CIDR_RE.fullmatch(bypass_cidr):
        return "Invalid file: missing or malformed 'bypass_cidr'"

    proxies = data.get("proxies")
    if not isinstance(proxies, dict) or not isinstance(proxies.get("profiles"), dict):
        return "Invalid file: missing or malformed 'proxies' section"
    for name, p in proxies["profiles"].items():
        if not isinstance(p, dict) or not REQUIRED_PROFILE_FIELDS.issubset(p.keys()):
            return f'Invalid file: proxy profile "{name}" is missing required fields'

    patterns = data.get("patterns")
    if not isinstance(patterns, dict) or not isinstance(patterns.get("rules"), list):
        return "Invalid file: missing or malformed 'patterns' section"
    for r in patterns["rules"]:
        if not isinstance(r, dict) or not REQUIRED_RULE_FIELDS.issubset(r.keys()):
            return "Invalid file: a pattern rule is missing required fields"
        if r["mode"] not in PATTERN_MODES:
            return f'Invalid file: unknown mode "{r["mode"]}" in a pattern rule'

    # Optional sections (absent from files exported before format 2).
    alerts = data.get("alerts")
    if alerts is not None:
        if not isinstance(alerts, dict) or not set(alerts) <= set(mailer_defaults()):
            return "Invalid file: malformed 'alerts' section"
    devices = data.get("devices")
    if devices is not None:
        if not isinstance(devices, dict) or not all(
                isinstance(mac, str) and MAC_RE.fullmatch(mac.lower()) and isinstance(d, dict)
                and isinstance(d.get("nickname", ""), str) and isinstance(d.get("blocked", False), bool)
                for mac, d in devices.items()):
            return "Invalid file: malformed 'devices' section"

    # Everything checked; now write. Proxies first: the firewall rebuilds
    # triggered by the next two calls resolve rule/default actions against
    # the profile list, so it must already reflect the imported data.
    save_store(proxies)
    save_pattern_config(patterns)
    set_bypass_cidr(bypass_cidr)
    if alerts is not None:
        save_alerts_config(dict(mailer_defaults(), **alerts))
    if devices is not None:
        store = load_devices_store()
        blocked_before = {mac for mac, d in store.items() if d.get("blocked")}
        now = datetime.now(timezone.utc).isoformat()
        for mac, d in devices.items():
            entry = store.setdefault(mac.lower(), {"mac": mac.lower(), "first_seen": now})
            if d.get("nickname"):
                entry["nickname"] = d["nickname"][:NICKNAME_MAX]
            entry["blocked"] = bool(d.get("blocked", False))
        save_devices_store(store)
        if {mac for mac, d in store.items() if d.get("blocked")} != blocked_before:
            apply_device_denylist(store)  # reconnects the hotspot, like Block/Unblock
    return None


_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
    '<text y=".9em" font-size="90">\U0001f512</text></svg>'
)
FAVICON = "data:image/svg+xml;base64," + base64.b64encode(_FAVICON_SVG.encode()).decode()

# Help content lives here, as plain Python strings, rather than inline in the
# Jinja2 template below — keeping quote nesting (Python string / Jinja2
# literal / HTML attribute / inline JS) out of the picture entirely, since
# that exact kind of nesting has caused real bugs elsewhere in this file.


def form_error(message, page, **kwargs):
    # A rejected form submission: the whole panel again, on the page the form
    # came from, with the error shown at the top (rather than a bare text page).
    return render(message, page=page, message_kind="error", **kwargs), 400


def render(message="", edit_name="", edit_pattern_id="", prefill=None, page="", message_kind="info", addition=None):
    store = load_store()
    hw = get_hardware_info()
    ssid = get_ap_ssid()
    wifi_band = get_wifi_band()
    wifi_radio = get_wifi_radio()
    hotspot_enabled = get_hotspot_enabled()
    live_devices = get_connected_devices()
    sync_traffic_accounting(live_devices)
    traffic = read_traffic_counters()
    devices = get_all_devices(live_devices)
    for d in devices:
        counts = traffic.get(d["ip"], {"up": 0, "down": 0}) if d["ip"] else {"up": 0, "down": 0}
        d["sent"] = format_bytes(counts["up"])
        d["received"] = format_bytes(counts["down"])
    bypass_cidr = get_bypass_cidr()
    pattern_config = load_pattern_config()
    pattern_rules = pattern_config["rules"]
    default_action = pattern_config["default_action"]
    edit_profile = store["profiles"].get(edit_name) if edit_name else None
    edit_pattern = next((r for r in pattern_rules if r["id"] == edit_pattern_id), None)
    form_pattern_list = rule_patterns(edit_pattern or prefill or {})
    if edit_pattern and addition and not addition["already"]:
        form_pattern_list = form_pattern_list + [addition["pattern"]]
    # Fixed set of known page slugs only — this is interpolated directly
    # into a <script> block in the template, so it must never carry
    # anything derived from request input.
    force_page = "proxy-profiles" if edit_name else ("pattern-rules" if edit_pattern_id or prefill else page)
    alerts = load_alerts_config()
    alerts_has_password = bool(alerts.pop("password", ""))
    profile_rules = {
        n: [rule_label(r) for r in pattern_rules if r["action"] == n and r.get("enabled", True)]
        for n in store["profiles"]
    }
    pattern_problems = {r["id"]: patterns_problem(rule_patterns(r), r["mode"]) for r in pattern_rules}
    lookups_snapshot = read_lookups_snapshot()
    doh_status = (lookups_snapshot or {}).get("doh") or {}
    health_status = read_health_status()
    rule_activity = get_rule_activity(pattern_rules, lookups_snapshot, health_status)
    return render_template(
        "admin.html",
        profiles=store["profiles"],
        action_choices=get_action_choices(),
        edit_name=edit_name,
        edit_profile=edit_profile,
        pattern_rules=pattern_rules,
        default_action=default_action,
        edit_pattern=edit_pattern,
        prefill=None if edit_pattern else prefill,
        alerts=alerts,
        alerts_has_password=alerts_has_password,
        profile_rules=profile_rules,
        pattern_problems=pattern_problems,
        resolve_via_proxy=pattern_config.get("resolve_via_proxy", True),
        rule_patterns=rule_patterns,
        addition=addition if edit_pattern else None,
        form_patterns="\n".join(form_pattern_list),
        form_pattern_rows=max(3, len(form_pattern_list) + 1),
        rule_presets=RULE_PRESETS,
        rule_activity=rule_activity,
        ago=ago,
        leak_guard_info=LEAK_GUARDS,
        leak_guards=pattern_config.get("leak_guards") or {k: True for k in LEAK_GUARDS},
        guard_counters=dict((health_status or {}).get("guard_counters") or {},
                            private_relay=((lookups_snapshot or {}).get("guard_hits") or {}).get("private_relay", 0)),
        HELP_LEAK_GUARDS=HELP_LEAK_GUARDS,
        doh_status=doh_status,
        HELP_RESOLVE_VIA_PROXY=HELP_RESOLVE_VIA_PROXY,
        hw=hw,
        ssid=ssid,
        wifi_band=wifi_band,
        wifi_radio=wifi_radio,
        wifi_radio_choices=wifi_radio_choices(wifi_radio),
        wifi_live_channel=live_wifi_frequency()[0],
        hotspot_enabled=hotspot_enabled,
        devices=devices,
        device_policies=pattern_config.get("device_policies") or {},
        profile_device_labels={n: list(profile_devices(n, pattern_config).values()) for n in store["profiles"]},
        profile_restore={n: restore_labels(n, p, pattern_config) if not p.get("enabled", True) else []
                         for n, p in store["profiles"].items()},
        nickname_max=NICKNAME_MAX,
        bypass_cidr=bypass_cidr,
        message=message,
        message_kind=message_kind if message_kind in ("info", "error") else "info",
        force_page=force_page,
        favicon=FAVICON,
        HELP_PROXY_PROFILES=HELP_PROXY_PROFILES,
        HELP_WIFI=HELP_WIFI,
        HELP_INTERNAL_NETWORK=HELP_INTERNAL_NETWORK,
        HELP_DEFAULT_BEHAVIOUR=HELP_DEFAULT_BEHAVIOUR,
        HELP_PATTERN_RULES=HELP_PATTERN_RULES,
        HELP_DEVICES=HELP_DEVICES,
        HELP_LOOKUPS=HELP_LOOKUPS,
        HELP_OVERVIEW=HELP_OVERVIEW,
        HELP_ALERTS=HELP_ALERTS,
        HELP_BACKUP_RESTORE=HELP_BACKUP_RESTORE,
        HELP_SYSTEM=HELP_SYSTEM,
        HELP_HELP=HELP_HELP,
        app_version=APP_VERSION,
        app_version_date=APP_VERSION_DATE,
    )


@app.route("/", methods=["GET"])
@require_auth
def index():
    return render(
        edit_name=request.args.get("edit", ""),
        edit_pattern_id=request.args.get("edit_pattern", ""),
        prefill=get_rule_prefill(request.args),
        addition=get_rule_addition(request.args, load_pattern_config()["rules"]),
    )


def get_rule_prefill(args):
    # "Add rule" links from the DNS Lookups page, and the preset picker,
    # pre-fill the Add Routing Rule form. Nothing is saved from these values:
    # the admin still reviews and submits the normal form, which validates as usual.
    preset = RULE_PRESETS.get(args.get("preset", ""))
    if preset:
        profiles = load_store()["profiles"]
        first = next((n for n, p in profiles.items() if p.get("enabled", True)), None)
        return {"patterns": list(preset["patterns"]), "mode": "wildcard",
                "action": first or "direct", "description": preset["description"]}
    pattern = args.get("new_pattern", "").strip().lower()
    if not pattern or len(pattern) > 253 or not re.fullmatch(r"[a-z0-9*?._-]+", pattern):
        return None
    mode = args.get("new_mode", "wildcard")
    action = args.get("new_action", "")
    valid_actions = {value for value, _ in get_action_choices()}
    return {
        "patterns": [pattern],
        "mode": mode if mode in PATTERN_MODES else "wildcard",
        "action": action if action in valid_actions else "direct",
        "description": args.get("new_desc", "").strip()[:120],
    }


@app.route("/proxy-profile/save", methods=["POST"])
@require_auth
def save_proxy_profile():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    proxy_type = request.form.get("type", "http-connect")
    ip = request.form.get("ip", "").strip()
    port = request.form.get("port", "").strip()
    login = request.form.get("login", "").strip()
    password = request.form.get("password", "")

    if not PROFILE_NAME_RE.fullmatch(name):
        return form_error("Invalid profile name (letters, numbers, spaces, - and _ only, max 40 chars)", "proxy-profiles")
    if proxy_type not in ("http-connect", "socks5"):
        return form_error("Invalid proxy type", "proxy-profiles")
    if not ip or not port.isdigit() or not (0 < int(port) < 65536):
        return form_error("Invalid address or port", "proxy-profiles")

    upsert_proxy_profile(name, description, proxy_type, ip, port, login, password)
    return render(f'Proxy profile "{name}" saved.')


@app.route("/proxy-profile/delete", methods=["POST"])
@require_auth
def delete_proxy_profile_route():
    name = request.form.get("name", "").strip()
    error = delete_proxy_profile(name)
    if error:
        return form_error(error, "proxy-profiles")
    return render(f'Proxy profile "{name}" deleted.')


@app.route("/proxy-profile/enabled", methods=["POST"])
@require_auth
def proxy_profile_enabled_route():
    # The page asks for confirmation first when disabling would also switch
    # off rules (see the toggle's onchange); this still enforces the rule
    # itself, whatever the browser did.
    name = request.form.get("name", "").strip()
    message, error = set_profile_enabled(name, request.form.get("enabled") == "1",
                                         restore=request.form.get("restore") == "1")
    if error == "Unknown proxy profile":
        return error, 400
    if error:
        return form_error(error, "proxy-profiles")
    return render(message, page="proxy-profiles")


@app.route("/proxy-profile/check", methods=["POST"])
@require_auth
def check_proxy_profile_route():
    # Plain dict return (Flask auto-JSON-encodes it), matching /api/traffic --
    # the only other JSON-returning route in this app. Always 200 with an
    # "ok" flag in the body, even on failure, since the failure itself
    # (proxy rejected auth, connection timed out, etc.) is the useful
    # result the button is asking for, not a server error.
    name = request.form.get("name", "").strip()
    store = load_store()
    profile = store["profiles"].get(name)
    if not profile:
        return {"ok": False, "error": "Unknown profile"}
    return check_proxy_profile(profile)


@app.route("/wifi", methods=["POST"])
@require_auth
def save_wifi():
    ssid = request.form.get("ssid", "").strip()
    passphrase = request.form.get("passphrase", "").strip()

    if not ssid:
        return form_error("SSID is required", "wifi")
    if passphrase and len(passphrase) < 8:
        return form_error("Passphrase must be at least 8 characters", "wifi")

    was_enabled = get_hotspot_enabled()
    set_ap_wifi(ssid, passphrase)
    if was_enabled:
        return render("Wi-Fi settings saved and access point restarted.")
    return render("Wi-Fi settings saved. The hotspot is currently disabled, so they won't take effect until you enable it.")


@app.route("/api/wifi-qr", methods=["GET"])
@require_auth
def api_wifi_qr():
    try:
        svg = get_wifi_qr_svg()
    except Exception:
        return Response("Couldn't read the hotspot's passphrase.", status=500, mimetype="text/plain")
    if svg is None:
        return Response("QR codes need the python3-qrcode package on the box (sudo apt install python3-qrcode).",
                        status=501, mimetype="text/plain")
    # It encodes the Wi-Fi password: never cache it anywhere.
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.route("/wifi/radio", methods=["POST"])
@require_auth
def wifi_radio_route():
    message, error = set_wifi_radio(request.form.get("choice", ""))
    if error:
        return form_error(error, "wifi")
    return render(message, page="wifi")


@app.route("/wifi/restart", methods=["POST"])
@require_auth
def restart_wifi():
    set_ap_wifi("", "")
    return render("Wi-Fi access point restarted.")


@app.route("/wifi/enabled", methods=["POST"])
@require_auth
def set_hotspot_enabled_route():
    enabled = request.form.get("enabled") == "1"
    set_hotspot_enabled(enabled)
    return render("Hotspot enabled." if enabled else "Hotspot disabled — it will stay off, even across a reboot, until re-enabled here.")


@app.route("/device/rename", methods=["POST"])
@require_auth
def rename_device_route():
    mac = request.form.get("mac", "").strip().lower()
    nickname = request.form.get("nickname", "")
    if not set_device_nickname(mac, nickname):
        return "Unknown device", 400
    return render("Device renamed." if nickname.strip() else "Device nickname removed.", page="devices")


@app.route("/device/policy", methods=["POST"])
@require_auth
def device_policy_route():
    mac = request.form.get("mac", "").strip().lower()
    message, error = set_device_policy(mac, request.form.get("action", ""))
    if error == "Unknown device":
        return error, 400
    if error:
        return form_error(error, "devices")
    return render(message, page="devices")


@app.route("/device/block", methods=["POST"])
@require_auth
def block_device_route():
    mac = request.form.get("mac", "").strip().lower()
    if not block_device(mac):
        return "Unknown device", 400
    return render("Device blocked.")


@app.route("/device/unblock", methods=["POST"])
@require_auth
def unblock_device_route():
    mac = request.form.get("mac", "").strip().lower()
    if not unblock_device(mac):
        return "Unknown device", 400
    return render("Device unblocked.")


@app.route("/system/reboot", methods=["POST"])
@require_auth
def reboot_system_route():
    reboot_system()
    return render("Rebooting now — the whole box, including this panel, will be unreachable for about a minute.")


@app.route("/api/traffic", methods=["GET"])
@require_auth
def api_traffic():
    # Read-only: just parses the existing kernel counters, no iptables
    # mutation, so the periodic in-page poll stays cheap even at a few
    # requests per minute per open browser tab.
    return read_traffic_counters()


@app.route("/api/signal", methods=["GET"])
@require_auth
def api_signal():
    # Same idea as /api/traffic: read-only (one `iw station dump`), polled
    # by the Devices page, keyed by MAC since that's what iw reports.
    return {
        mac: {"dbm": s["signal_dbm"], "bars": s["signal_bars"], "label": s["signal_label"]}
        for mac, s in get_station_dump().items()
    }


@app.route("/api/health", methods=["GET"])
@require_auth
def api_health():
    # Read-only: just the latest status file written by rasp-proxy-health.
    return get_health_view()


@app.route("/health/run", methods=["POST"])
@require_auth
def health_run_route():
    try:
        run_health_check_now()
        return {"ok": True}
    except Exception:
        return {"ok": False, "error": "Couldn't start the health check"}


@app.route("/alerts/save", methods=["POST"])
@require_auth
def alerts_save_route():
    config, error = parse_alerts_form(request.form, load_alerts_config())
    if error:
        return form_error(error, "system")
    save_alerts_config(config)
    return render("Email alert settings saved." + ("" if config["enabled"] else " Alerts are off."), page="system")


@app.route("/alerts/test", methods=["POST"])
@require_auth
def alerts_test_route():
    # Sends with the values currently in the form (not yet saved), so the
    # settings can be tried before saving them. JSON, like /proxy-profile/check.
    config, error = parse_alerts_form(request.form, load_alerts_config())
    if error:
        return {"ok": False, "error": error}
    error = send_email(
        config,
        f"[{socket.gethostname()}] Test email from the Wi-Fi Proxy Hotspot",
        "This is a test from the admin panel's Email Alerts settings.\n\n"
        "If you're reading it, alerts will reach you: you'll get an email when a health check starts "
        "failing (after two checks in a row, about 4 minutes), another when it recovers, and one-off "
        "notices such as the box restarting or under-voltage.\n",
    )
    return {"ok": error is None, "error": error}


@app.route("/api/rule-test", methods=["GET"])
@require_auth
def api_rule_test():
    return explain_hostname(request.args.get("host", ""))


@app.route("/api/lookups", methods=["GET"])
@require_auth
def api_lookups():
    # Read-only, polled by the DNS Lookups page only while it's the one open.
    return get_lookups_view()


@app.route("/network", methods=["POST"])
@require_auth
def save_network():
    cidr = request.form.get("bypass_cidr", "").strip()

    if not CIDR_RE.fullmatch(cidr):
        return form_error("Invalid CIDR (expected e.g. 192.168.1.0/24)", "network")

    set_bypass_cidr(cidr)
    return render("Internal network settings saved.")


@app.route("/pattern-rule/save", methods=["POST"])
@require_auth
def save_pattern_rule():
    rule_id = request.form.get("id", "").strip()
    # "patterns" is the form's one-per-line box; "pattern" is still accepted.
    patterns = parse_patterns(request.form.get("patterns", request.form.get("pattern", "")))
    mode = request.form.get("mode", "wildcard")
    action = request.form.get("action", "direct")
    description = request.form.get("description", "").strip()

    valid_actions = {value for value, _ in get_action_choices()}
    if mode not in PATTERN_MODES:
        return "Invalid mode", 400
    if action not in valid_actions:
        return "Invalid action", 400
    problem = patterns_problem(patterns, mode)
    if problem:
        # Keep what was typed: a new rule's form re-opens pre-filled with it.
        keep = None if rule_id else {"patterns": [p[:253] for p in patterns[:MAX_PATTERNS_PER_RULE]],
                                     "mode": mode, "action": action, "description": description[:120]}
        return form_error(problem, "pattern-rules", edit_pattern_id=rule_id, prefill=keep)

    if not upsert_pattern_rule(rule_id, patterns, mode, action, description):
        return "Unknown pattern rule", 400
    return render("Routing rule saved." + rule_notes(patterns, mode, action))


@app.route("/pattern-rule/delete", methods=["POST"])
@require_auth
def delete_pattern_rule_route():
    delete_pattern_rule(request.form.get("id", "").strip())
    return render("Routing rule deleted.")


@app.route("/pattern-rule/toggle", methods=["POST"])
@require_auth
def toggle_pattern_rule_route():
    rule_id = request.form.get("id", "").strip()
    if not toggle_pattern_rule(rule_id):
        return "Unknown pattern rule", 400
    rule = next((r for r in load_pattern_rules() if r["id"] == rule_id), None)
    notes = rule_notes(rule_patterns(rule), rule["mode"], rule["action"]) if rule and rule.get("enabled", True) else ""
    return render("Routing rule updated." + notes)


@app.route("/pattern-rule/move", methods=["POST"])
@require_auth
def move_pattern_rule_route():
    rule_id = request.form.get("id", "").strip()
    direction = request.form.get("direction", "")
    if direction not in ("up", "down"):
        return "Invalid direction", 400
    move_pattern_rule(rule_id, direction)
    return render()


@app.route("/resolve-via-proxy", methods=["POST"])
@require_auth
def resolve_via_proxy_route():
    config = load_pattern_config()
    config["resolve_via_proxy"] = request.form.get("enabled") == "1"
    save_pattern_config(config)  # also clears dnsmasq's cache, so it applies straight away
    if config["resolve_via_proxy"]:
        return render("Proxied rules' hostnames are now looked up through their proxy.", page="pattern-rules")
    return render("Proxied rules' hostnames are now looked up with ordinary DNS again.", page="pattern-rules")


@app.route("/leak-guard", methods=["POST"])
@require_auth
def leak_guard_route():
    name = request.form.get("name", "")
    if name not in LEAK_GUARDS:
        return "Unknown leak guard", 400
    config = load_pattern_config()
    config["leak_guards"][name] = request.form.get("enabled") == "1"
    save_pattern_config(config)  # rebuilds the firewall and clears dnsmasq's cache
    label = LEAK_GUARDS[name][0]
    return render(f'"{label}" turned {"on" if config["leak_guards"][name] else "off"}.', page="pattern-rules")


@app.route("/default-action/save", methods=["POST"])
@require_auth
def save_default_action():
    action = request.form.get("default_action", "")
    valid_actions = {value for value, _ in get_action_choices()}
    if action not in valid_actions:
        return "Invalid action", 400
    profile = load_store()["profiles"].get(action)
    if profile and not profile.get("enabled", True):
        # Mirrors set_profile_enabled(): the default's profile can't be disabled.
        return form_error(f'"{action}" is disabled. Enable it on the Proxy Profiles page first, '
                          "or pick a different default.", "pattern-rules")
    set_default_action(action)
    return render("Default behaviour saved.")


@app.route("/help/guide.pdf", methods=["GET"])
@require_auth
def help_guide_pdf():
    if not os.path.exists(GUIDE_PDF_PATH):
        return "Guide not installed on this box — re-run install.sh to deploy it.", 404
    return send_file(GUIDE_PDF_PATH, mimetype="application/pdf")


@app.route("/config/export", methods=["GET"])
@require_auth
def export_config_route():
    payload = json.dumps(export_config(), indent=2).encode()
    return send_file(
        io.BytesIO(payload),
        mimetype="application/json",
        as_attachment=True,
        download_name="wifi-proxy-hotspot-config.json",
    )


@app.route("/config/import", methods=["POST"])
@require_auth
def import_config_route():
    file = request.files.get("file")
    if not file or not file.filename:
        return form_error("No file uploaded", "backup-restore")
    try:
        data = json.load(file)
    except ValueError:
        return form_error("Invalid file: not valid JSON", "backup-restore")

    error = import_config(data)
    if error:
        return form_error(error, "backup-restore")
    return render("Configuration imported successfully.", page="backup-restore")
