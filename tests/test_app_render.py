"""The whole admin page, rendered for representative scenarios with every
OS call faked -- the automated form of the manual render check:
balanced tags, no <dialog> inside a heading, every inline <script> passes
`node --check`, balanced <style> braces."""
import copy
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

import mailer
from conftest import SAMPLE_PROFILES, FakeRun, sample_rules

IW_DUMP = (
    "Station aa:bb:cc:dd:ee:01 (on wlan0)\n\tsignal:  \t-48 [-50] dBm\n\tsignal avg:\t-47 [-49] dBm\n"
    "\tconnected time:\t3600 seconds\n"
    "Station AA:BB:CC:DD:EE:02 (on wlan0)\n\tsignal:  \t-73 dBm\n\tconnected time:\t60 seconds\n"
    "Station aa:bb:cc:dd:ee:03 (on wlan0)\n\tconnected time:\t5 seconds\n"
)
LEASES = "1790000000 aa:bb:cc:dd:ee:01 192.168.4.71 laptop *\n1790000000 aa:bb:cc:dd:ee:02 192.168.4.80 * *\n"


def render_page(app, monkeypatch, profiles=None, rules=None, hotspot=True, devices=None, config_extra=None,
                **render_kwargs):
    store = {"profiles": copy.deepcopy(profiles if profiles is not None else SAMPLE_PROFILES), "next_port": 20002}
    config = {"bypass_cidr": "192.168.1.0/24", "default_action": "direct",
              "rules": rules if rules is not None else sample_rules(), **(config_extra or {})}
    known = devices if devices is not None else {
        "11:22:33:44:55:66": {"mac": "11:22:33:44:55:66", "hostname": "old-phone", "blocked": True}}
    fake = FakeRun([(["iw", "dev"], IW_DUMP), (["sudo", "-n", "/bin/cat"], LEASES)])
    with monkeypatch.context() as m:
        m.setattr(subprocess, "run", fake)
        m.setattr(app, "load_store", lambda: store)
        m.setattr(app, "get_ap_ssid", lambda: "TestSSID")
        m.setattr(app, "get_wifi_band", lambda: "2.4 GHz")
        m.setattr(app, "get_hotspot_enabled", lambda: hotspot)
        m.setattr(app, "sync_traffic_accounting", lambda d: None)
        m.setattr(app, "read_traffic_counters", lambda: {"192.168.4.71": {"up": 12345, "down": 9876543}})
        m.setattr(app, "load_devices_store", lambda: known)
        m.setattr(app, "save_devices_store", lambda s: None)
        m.setattr(app, "get_bypass_cidr", lambda: "192.168.1.0/24")
        m.setattr(app, "load_pattern_config", lambda: config)
        m.setattr(app, "load_alerts_config", lambda: dict(mailer.DEFAULTS, password="secret-smtp"))
        with app.app.test_request_context("/"):
            return app.render(**render_kwargs)


class Balance(HTMLParser):
    VOID = {"meta", "link", "input", "br", "img", "hr"}

    def __init__(self):
        super().__init__()
        self.stack, self.errors = [], []

    def handle_starttag(self, tag, attrs):
        if tag == "dialog" and any(t in ("h1", "h2", "h3") for t in self.stack):
            self.errors.append("<dialog> inside a heading")
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"mismatched </{tag}> (open: {self.stack[-3:]})")
            while tag in self.stack and self.stack.pop() != tag:
                pass
        else:
            self.stack.pop()


def check_page(html, tmp_path):
    b = Balance()
    b.feed(html)
    assert b.errors == [] and b.stack == [], (b.errors, b.stack)
    for style in re.findall(r"<style>(.*?)</style>", html, re.S):
        assert style.count("{") == style.count("}")
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts
    node = shutil.which("node")
    if not node and os.environ.get("CI"):
        pytest.fail("node is required in CI: the inline-script syntax check must not be skipped there")
    if node:
        # One node run per page: each script in its own block, marked so a
        # syntax error's line number points back at the right <script>.
        path = tmp_path / "inline.js"
        path.write_text("".join(f"// ---- inline script {i}\n{{\n{js}\n}}\n" for i, js in enumerate(scripts)),
                        encoding="utf-8")
        result = subprocess.run([node, "--check", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_check_page_catches_a_broken_inline_script(tmp_path):
    # The real bug from 2026-10-01: a \n inside the Python PAGE string became a
    # literal newline inside a JS string, breaking the whole <script>.
    broken = "<title>x</title><style>a{}</style><script>alert('a\nb');</script>"
    with pytest.raises(AssertionError):
        check_page(broken, tmp_path)


SCENARIOS = {
    "normal": {},
    "prefilled rule": {"prefill": {"patterns": ["*.netrw.it"], "mode": "wildcard", "action": "Remote Proxy",
                                   "description": "Found in DNS lookups"}},
    "error message": {"message": 'Can\'t disable "x": it\'s the <Default>', "message_kind": "error", "page": "proxy-profiles"},
    "editing a profile": {"edit_name": "Backup Proxy"},
    "editing a rule": {"edit_pattern_id": "r1"},
}


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_page_is_well_formed(app_module, monkeypatch, tmp_path, scenario):
    check_page(render_page(app_module, monkeypatch, **SCENARIOS[scenario]), tmp_path)


def test_hotspot_off_and_no_profiles_or_rules(app_module, monkeypatch, tmp_path):
    check_page(render_page(app_module, monkeypatch, profiles={}, rules=[], hotspot=False), tmp_path)


def test_mobile_viewport_and_stacked_tables(app_module, monkeypatch):
    html = render_page(app_module, monkeypatch)
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html
    assert html.count('class="stack"') == 4  # profiles, pattern rules, devices, DNS lookups


def test_devices_signal_column(app_module, monkeypatch):
    html = render_page(app_module, monkeypatch)
    assert "signal-bars signal-4" in html and "-47 dBm · Excellent" in html   # "signal avg" preferred
    assert "signal-bars signal-1" in html and "-73 dBm · Weak" in html         # instantaneous fallback


def test_messages_are_escaped_and_marked(app_module, monkeypatch):
    html = render_page(app_module, monkeypatch, **SCENARIOS["error message"])
    assert 'class="msg msg-error" role="alert"' in html
    assert "&lt;Default&gt;" in html and "<Default>" not in html


def test_prefill_opens_form_with_values(app_module, monkeypatch):
    html = render_page(app_module, monkeypatch, **SCENARIOS["prefilled rule"])
    assert '>*.netrw.it</textarea>' in html and '<details class="add-profile" open' in html
    assert '<option value="Remote Proxy" selected' in html
    assert 'var forced = "pattern-rules"' in html


def test_disabled_profile_row_and_warning(app_module, monkeypatch):
    profiles = copy.deepcopy(SAMPLE_PROFILES)
    profiles["Remote Proxy"]["enabled"] = False            # r1 (enabled) still uses it
    html = render_page(app_module, monkeypatch, profiles=profiles)
    assert "Still used by an enabled rule" in html
    assert "Remote Proxy — Abroad (disabled)</option>" in html
    assert """data-rules='["TV8 live"]'""" in html            # the confirmation dialog's rule list


def test_secrets_never_reach_the_page(app_module, monkeypatch):
    html = render_page(app_module, monkeypatch, edit_name="Remote Proxy")
    assert "secret-smtp" not in html                         # SMTP password
    assert 'name="password" type="password" placeholder="leave blank to keep current"' in html
    assert 'value="p"' not in html                            # proxy password of the edited profile


def test_proxied_lookups_section_and_status(app_module, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "read_lookups_snapshot", lambda: {"doh": {
        "Remote Proxy": {"warm": 2, "ok": 40, "fallback": 1, "last_error": ""}}})
    html = render_page(app_module, monkeypatch)
    check_page(html, tmp_path)
    assert 'action="/resolve-via-proxy"' in html and "Proxied Lookups" in html
    assert "2 tunnels ready · 40 lookups through the proxy, 1 fell back to ordinary DNS" in html


def test_unmatchable_rule_gets_badge(app_module, monkeypatch):
    rules = sample_rules() + [{"id": "r9", "pattern": "*.discoveryplus.com/*", "mode": "wildcard",
                               "action": "Remote Proxy", "description": "D+", "enabled": True}]
    html = render_page(app_module, monkeypatch, rules=rules)
    assert "can never match: rules match hostnames only" in html
