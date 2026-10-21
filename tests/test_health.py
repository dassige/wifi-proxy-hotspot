"""rasp-proxy-health, run several times in a row against a faked box, to check
the alerting state machine: debounce, queue-and-retry, recovery, one-off
notices, disabled/unused profiles, crash isolation, no leaked secrets."""
import io
import json
import os
import subprocess

import pytest

import mailer
from conftest import load_script

health = load_script("rasp-proxy-health.py", "rasp_proxy_health")
SECRET = "S3cr3t-proxy-pass"
SMTP_PW = "smtp-pw"


class Box:
    """The faked world one health run sees; tests flip its attributes between runs."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.redsocks = "active"
        self.proxy_ok = True
        self.country = "IT"
        self.boot = "boot-1"
        self.nat_rules = 3
        self.smtp_up = False
        self.sent = []
        self.checked = []
        self.now = None                                            # None: the real clock
        # Limits off unless a test sets them, so the basic state machine is tested on its own.
        self.alerts = dict(mailer.DEFAULTS, enabled=True, smtp_host="smtp.example.com", recipients="me@example.com",
                           password=SMTP_PW, recover_after_min=0, min_interval_min=0)
        self.profiles = {
            "default": {"type": "http-connect", "ip": "1.2.3.4", "port": "8080", "login": "u",
                        "password": SECRET, "local_port": 20000},
            "Backup Proxy": {"type": "http-connect", "ip": "5.6.7.8", "port": "8888", "login": "",
                        "password": "", "local_port": 20002},
        }
        self.write("rules.json", {"bypass_cidr": "192.168.1.0/24", "default_action": "direct", "rules": [
            {"id": "aaaa0001", "pattern": "*.netrw.it", "mode": "wildcard", "action": "default", "enabled": True},
            {"id": "aaaa0002", "pattern": "*.old.it", "mode": "wildcard", "action": "Backup Proxy", "enabled": False}]})
        self.write("lookups.json", {"generated": 9e12, "capture": "ok", "clients": {"192.168.4.71": []}})

    def path(self, name):
        return str(self.tmp / name)

    def write(self, name, data):
        (self.tmp / name).write_text(json.dumps(data))

    def run_cmd(self, cmd, timeout=15):
        out, code = "", 0
        if cmd[:2] == ["systemctl", "is-active"]:
            out = self.redsocks if cmd[2] == "redsocks" else "active"
        elif cmd[:2] == ["systemctl", "show"]:
            out = "ActiveState=active\nResult=success\n"
        elif cmd[:2] == ["nmcli", "-g"]:
            out = "yes\n"
        elif cmd[:3] == ["nmcli", "-t", "-f"]:
            out = "Gateway-AP\neth0\n"
        elif cmd[0] == "iw":
            out = "Station aa (on wlan0)\n"
        elif cmd[:3] == ["ip", "-4", "-o"]:
            out = "5: wlan0    inet 192.168.4.1/24 brd 192.168.4.255 scope global wlan0\n"
        elif cmd[0] in ("iptables", "ip6tables") and "-S" in cmd:
            chain = cmd[-1]
            count = {"REDSOCKS": self.nat_rules, "WPXQUIC": 3, "WPXDNS": 4, "WPXGUARD": 3,
                     "WPXGUARD6": 1}.get(chain, 0)
            out = f"-N {chain}\n" + f"-A {chain} x\n" * count
        elif cmd[:3] == ["ipset", "list", "-n"]:
            out = "wpx_aaaa0001\n"
        return subprocess.CompletedProcess(cmd, code, out, "")

    def check_proxy(self, profile):
        self.checked.append(profile["ip"])
        if profile["ip"] == "5.6.7.8":
            return {"ok": False, "error": "Could not connect to proxy: timed out", "timings": {}}
        if self.proxy_ok:
            return {"ok": True, "error": None, "timings": {"total_ms": 5200}}
        return {"ok": False, "error": "Proxy rejected CONNECT: HTTP/1.1 407", "timings": {}}

    def send(self, cfg, subject, body, timeout=20):
        if not self.smtp_up:
            return "ConnectionRefusedError: [Errno 111] Connection refused"
        self.sent.append((subject, body))
        return None


@pytest.fixture
def box(tmp_path, monkeypatch):
    b = Box(tmp_path)
    real_open = open
    virtual = {
        "/proc/sys/kernel/random/boot_id": lambda: b.boot,
        "/proc/uptime": lambda: "1000.0 500.0",
        "/run/nm-dnsmasq-wlan0.pid": lambda: "5510\n",
        "/proc/5510/comm": lambda: "dnsmasq\n",
    }
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: io.StringIO(virtual[p]()) if p in virtual
                        else real_open(p, *a, **k))
    monkeypatch.setattr(health, "run", b.run_cmd)
    monkeypatch.setattr(health, "dns_probe", lambda *a, **k: (True, "answered in 30 ms"))
    monkeypatch.setattr(health, "check_internet",
                        lambda: [health.check("internet", "Hotspot & DNS", "Internet (direct)", "ok", "ok")])
    monkeypatch.setattr(health, "check_proxy_profile", b.check_proxy)
    monkeypatch.setattr(health, "get_exit_info",
                        lambda p: {"ip": "89.1.1.1", "country": b.country, "city": "Milan", "org": "x"})
    monkeypatch.setattr(health, "send_email", b.send)
    monkeypatch.setattr(health, "load_alerts_config", lambda: dict(b.alerts))
    for attr, name in (("PROXY_STORE", "proxies.json"), ("RULES_FILE", "rules.json"), ("LOOKUPS_FILE", "lookups.json"),
                       ("STATUS_FILE", "status.json"), ("STATE_FILE", "state.json")):
        monkeypatch.setattr(health, attr, b.path(name))
    monkeypatch.setattr(health, "STATUS_DIR", str(tmp_path))
    monkeypatch.setattr(health.os, "chown", lambda *a: None, raising=False)

    def run_once():
        b.write("proxies.json", {"profiles": b.profiles})
        health.main(b.now)
        return (json.loads((tmp_path / "status.json").read_text()),
                json.loads((tmp_path / "state.json").read_text()))

    b.run_once = run_once
    return b


def by_id(status):
    return {c["id"]: c for c in status["checks"]}


def test_healthy_box_with_unused_proxy_down(box):
    s, st = box.run_once()
    c = by_id(s)
    assert s["overall"] == "warn"                                  # unused proxy down -> amber only
    assert c["proxy:Backup Proxy"]["status"] == "warn" and not c["proxy:Backup Proxy"]["alert"]
    assert "exit IP 89.1.1.1, geolocated Milan, IT" in c["proxy:default"]["detail"]
    assert c["firewall"]["status"] == "ok"                         # 1 enabled rule + bypass + default
    assert c["svc:redsocks"]["status"] == "ok" and c["dns:capture"]["status"] == "ok"
    assert st["pending"] == [] and box.sent == []


def test_debounce_queue_retry_and_recovery(box):
    box.run_once()
    box.redsocks, box.proxy_ok = "failed", False
    s, st = box.run_once()
    assert st["pending"] == []                                     # one bad run: not yet
    s, st = box.run_once()
    assert [m["kind"] for m in st["pending"]] == ["PROBLEM", "PROBLEM"]
    assert s["alerts"]["pending"] == 2 and "Connection refused" in s["alerts"]["last_error"]
    s, st = box.run_once()
    assert len(st["pending"]) == 2                                 # no duplicates while still failing
    box.redsocks, box.proxy_ok, box.smtp_up = "active", True, True
    s, st = box.run_once()
    assert len(box.sent) == 1 and st["pending"] == []
    subject, body = box.sent[0]
    # Everything in it has recovered by the time it goes out, so the subject says so.
    assert subject.startswith(f"[{health.HOSTNAME}] RECOVERED: ") and "(+3 more)" in subject
    assert body.count("PROBLEM") == 2 and body.count("RECOVERED") == 2 and "was down about" in body


def test_firewall_incomplete_alerts_then_recovers(box):
    box.smtp_up = True
    box.nat_rules = 2
    box.run_once()
    box.run_once()
    assert "REDSOCKS has 2 rules, expected 3" in box.sent[-1][1]
    box.nat_rules = 3
    box.run_once()
    assert "RECOVERED" in box.sent[-1][0]


def test_notices_exit_change_and_restart(box):
    box.smtp_up = True
    box.run_once()
    state = json.loads((box.tmp / "state.json").read_text())
    state["exit"]["default"]["checked"] = 0                        # force the 30-minute re-check
    (box.tmp / "state.json").write_text(json.dumps(state))
    box.country, box.boot = "DE", "boot-2"
    box.run_once()
    body = box.sent[-1][1]
    assert "exit changed: now 89.1.1.1 (geolocated DE), was 89.1.1.1 (IT)" in body
    assert "restarted: up since" in body


def test_disabled_profiles_are_not_checked_and_never_alert(box):
    box.smtp_up, box.proxy_ok = True, False
    box.profiles["Backup Proxy"]["monitored"] = False                   # legacy key name still honoured
    box.profiles["default"]["enabled"] = False                     # still used by rule aaaa0001
    for _ in range(3):
        s, st = box.run_once()
    c = by_id(s)
    assert box.checked == [] and box.sent == [] and s["overall"] == "ok"
    assert c["proxy:Backup Proxy"]["status"] == "off"
    assert "still used by an enabled rule" in c["proxy:default"]["detail"]
    assert [x["id"] for x in s["checks"] if x["group"] == "Proxies"] == ["proxy:default", "proxy:Backup Proxy"]
    box.profiles["default"]["enabled"] = True
    box.run_once()
    box.run_once()
    assert "1.2.3.4" in box.checked and len(box.sent) == 1


def test_flapping_proxy_sends_one_problem_and_one_recovery(box):
    box.smtp_up, box.alerts["recover_after_min"] = True, 10
    box.now = 1_000_000.0

    def run(proxy_ok, minutes=2):
        box.proxy_ok = proxy_ok
        s, st = box.run_once()
        box.now += minutes * 60
        return s, st

    run(True)
    run(False)
    run(False)
    assert [m[0].split(": ")[0] for m in box.sent] == [f"[{health.HOSTNAME}] PROBLEM"]
    for _ in range(5):                                             # up 4 min, down 2 min, all day long
        run(True)
        run(True)
        run(False)
    s, st = box.run_once()
    assert len(box.sent) == 1 and st["checks"]["proxy:default"]["relapses"] == 5
    assert st["checks"]["proxy:default"]["alerting"] and by_id(s)["proxy:default"]["status"] == "fail"
    for _ in range(6):                                             # finally stays up for 10 minutes
        run(True)
    subject, body = box.sent[-1]
    assert len(box.sent) == 2 and "RECOVERED" in subject
    assert "was down about 34 min, failed again 5x before staying up" in body
    st = json.loads((box.tmp / "state.json").read_text())
    assert "good_since" not in st["checks"]["proxy:default"]          # nothing left over once closed


def test_emails_are_grouped_by_the_minimum_interval(box):
    box.smtp_up, box.alerts["min_interval_min"] = True, 30
    box.now = 1_000_000.0
    box.redsocks = "failed"
    box.run_once()
    box.run_once()
    assert len(box.sent) == 1                                      # first one after a quiet spell: at once
    box.now += 4 * 60
    box.redsocks = "active"
    s, st = box.run_once()                                         # recovery: held
    assert len(box.sent) == 1 and len(st["pending"]) == 1
    assert s["alerts"]["held_until"] == 1_000_000.0 + 1800 and s["alerts"]["min_interval_min"] == 30
    box.now += 4 * 60
    box.redsocks = "failed"
    box.run_once()
    box.run_once()                                                 # down again: held too
    box.now = 1_000_000.0 + 1800
    s, st = box.run_once()
    assert len(box.sent) == 2 and st["pending"] == [] and s["alerts"]["held_until"] is None
    subject, body = box.sent[-1]
    assert "PROBLEM" in subject and "(+1 more)" in subject         # it's down again right now
    assert "2 alerts since" in body and "at most one every 30 min" in body


def test_clock_going_backwards_does_not_hold_mail_forever(box):
    box.smtp_up, box.alerts["min_interval_min"] = True, 30
    box.now = 2_000_000.0
    box.redsocks = "failed"
    box.run_once()
    box.run_once()
    box.now, box.redsocks = 1_000_000.0, "active"
    box.run_once()
    assert len(box.sent) == 2


def test_alert_limits_tolerate_bad_values():
    assert mailer.alert_limit({}, "min_interval_min") == 30
    assert mailer.alert_limit({"min_interval_min": "x"}, "min_interval_min") == 30
    assert mailer.alert_limit({"min_interval_min": -5}, "min_interval_min") == 0
    assert mailer.alert_limit({"recover_after_min": 10**9}, "recover_after_min") == 240


def test_one_crashing_check_does_not_hide_the_rest(box, monkeypatch):
    monkeypatch.setattr(health, "check_firewall", lambda rules: 1 / 0)
    s, _ = box.run_once()
    ids = [c["id"] for c in s["checks"]]
    assert any(i.startswith("internal:") for i in ids) and "svc:redsocks" in ids


def test_secrets_never_leave_the_box(box):
    box.smtp_up = True
    box.proxy_ok = False
    for _ in range(3):
        s, _ = box.run_once()
    everything = json.dumps(s) + (box.tmp / "state.json").read_text() + json.dumps(box.sent)
    assert SECRET not in everything and SMTP_PW not in everything


def test_state_file_untouched_when_nothing_changes(box):
    box.run_once()
    box.run_once()
    before = os.stat(box.path("state.json")).st_mtime_ns
    box.run_once()
    assert os.stat(box.path("state.json")).st_mtime_ns == before     # spares the SD card


def test_dns_probe_without_a_server_fails_cleanly():
    ok, detail = health.dns_probe("127.0.0.1", 9, timeout=1)
    assert not ok and detail
