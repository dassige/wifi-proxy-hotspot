"""Batch G: Wi-Fi join QR code, band/channel switching with automatic revert,
toasts + dark mode on the page."""
import subprocess
import sys

import pytest

from conftest import FakeRun
from test_app_render import check_page, render_page

PSK = "S3cret;pass:word"


def test_qr_payload_escapes_special_characters(app_module):
    assert app_module.wifi_qr_payload('My;Net,"x"', "a\\b:c") == 'WIFI:T:WPA;S:My\\;Net\\,\\"x\\";P:a\\\\b\\:c;;'


def test_qr_svg_built_from_nm_secret(app_module, monkeypatch):
    pytest.importorskip("qrcode")
    import qrcode

    seen = {}
    real_make = qrcode.make
    monkeypatch.setattr(qrcode, "make", lambda data, **k: seen.setdefault("data", data) and real_make(data, **k))
    fake = FakeRun([(["sudo", "-n", "/usr/bin/nmcli", "-s", "-g"], PSK + "\n"),
                    (["nmcli", "-g", "802-11-wireless.ssid"], "DGSoft_one_proxy\n")])
    monkeypatch.setattr(subprocess, "run", fake)
    svg = app_module.get_wifi_qr_svg()
    assert svg.lstrip().startswith("<") and "<svg" in svg and PSK not in svg
    assert seen["data"] == "WIFI:T:WPA;S:DGSoft_one_proxy;P:S3cret\\;pass\\:word;;"
    assert ["sudo", "-n", "/usr/bin/nmcli", "-s", "-g", "802-11-wireless-security.psk",
            "connection", "show", "Gateway-AP"] in fake.commands()


def test_qr_route_no_store_missing_package_and_errors(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "get_wifi_qr_svg", lambda: "<svg></svg>")
    with app_module.app.test_request_context("/api/wifi-qr"):
        r = app_module.api_wifi_qr.__wrapped__()
    assert r.mimetype == "image/svg+xml" and r.headers["Cache-Control"] == "no-store"
    monkeypatch.setattr(app_module, "get_wifi_qr_svg", lambda: None)
    with app_module.app.test_request_context("/api/wifi-qr"):
        r = app_module.api_wifi_qr.__wrapped__()
    assert r.status_code == 501 and "python3-qrcode" in r.get_data(as_text=True)

    def boom():
        raise RuntimeError(f"nmcli said {PSK}")

    monkeypatch.setattr(app_module, "get_wifi_qr_svg", boom)
    with app_module.app.test_request_context("/api/wifi-qr"):
        r = app_module.api_wifi_qr.__wrapped__()
    assert r.status_code == 500 and PSK not in r.get_data(as_text=True)


def test_qr_without_the_package(app_module, monkeypatch):
    monkeypatch.setitem(sys.modules, "qrcode", None)
    assert app_module.get_wifi_qr_svg() is None


# --- band / channel -------------------------------------------------------------------

class Radio:
    """Fake nmcli + iw for set_wifi_radio: `starts` decides whether the radio
    comes up on 5 GHz, and records every command."""

    def __init__(self, band="bg", channel="0", active=True, starts=True, hang=False, refuse=False):
        self.band, self.channel, self.active, self.starts, self.hang = band, channel, active, starts, hang
        self.refuse = refuse
        self.cmds = []

    def __call__(self, cmd, *a, **k):
        self.cmds.append(list(cmd))
        out, code = "", 0
        if cmd[:2] == ["nmcli", "-g"] and "802-11-wireless.band,802-11-wireless.channel" in cmd:
            out = f"{self.band}\n{self.channel}\n"
        elif cmd[:3] == ["nmcli", "-t", "-f"]:
            out = "Gateway-AP\n" if self.active else ""
        elif "modify" in cmd:
            channel = cmd[cmd.index("802-11-wireless.channel") + 1]
            if channel == "0" or self.refuse:  # real nmcli: "'0' is not a valid channel"
                if k.get("check"):
                    raise subprocess.CalledProcessError(2, cmd)
                return subprocess.CompletedProcess(cmd, 2, "", "Error")
            self.band, self.channel = cmd[cmd.index("802-11-wireless.band") + 1], channel or "0"
        elif cmd[-2:] == ["up", "Gateway-AP"]:
            if self.hang and self.band == "a":
                raise subprocess.TimeoutExpired(cmd, 60)
        elif cmd[:2] == ["iw", "dev"]:
            on_5 = self.band == "a" and self.starts
            ch, freq = (self.channel, 5180) if on_5 else ("11", 2462)
            out = f"Interface wlan0\n\ttype AP\n\tchannel {ch} ({freq} MHz), width: 20 MHz\n"
        return subprocess.CompletedProcess(cmd, code, out, "")


@pytest.fixture
def no_sleep(app_module, monkeypatch):
    monkeypatch.setattr(app_module.time, "sleep", lambda s: None)


def test_switch_to_5ghz(app_module, monkeypatch, no_sleep):
    radio = Radio()
    monkeypatch.setattr(subprocess, "run", radio)
    msg, err = app_module.set_wifi_radio("a:36")
    assert err is None and "5 GHz, channel 36" in msg and "live: channel 36, 5180 MHz" in msg
    assert (radio.band, radio.channel) == ("a", "36")


@pytest.mark.parametrize("starts,hang", [(False, False), (True, True)])
def test_failed_switch_reverts(app_module, monkeypatch, no_sleep, starts, hang):
    radio = Radio(band="bg", channel="6", starts=starts, hang=hang)
    monkeypatch.setattr(subprocess, "run", radio)
    msg, err = app_module.set_wifi_radio("a:149")
    assert msg is None and "couldn't start on 5 GHz, channel 149" in err and "2.4 GHz, channel 6" in err
    assert (radio.band, radio.channel) == ("bg", "6")
    assert [c for c in radio.cmds if c[-2:] == ["up", "Gateway-AP"]][-1]       # brought back up after revert


def test_back_to_automatic_uses_an_empty_channel(app_module, monkeypatch, no_sleep):
    radio = Radio(band="a", channel="36")
    monkeypatch.setattr(subprocess, "run", radio)
    msg, err = app_module.set_wifi_radio("bg:0")
    assert err is None and "2.4 GHz, automatic channel" in msg
    modify = next(c for c in radio.cmds if "modify" in c)
    assert modify[-2:] == ["802-11-wireless.channel", ""]                 # nmcli rejects "0"


def test_5ghz_automatic(app_module, monkeypatch, no_sleep):
    radio = Radio()
    monkeypatch.setattr(subprocess, "run", radio)
    msg, err = app_module.set_wifi_radio("a:0")
    assert err is None and "5 GHz, automatic channel" in msg
    modify = next(c for c in radio.cmds if "modify" in c)
    assert modify[-4:] == ["802-11-wireless.band", "a", "802-11-wireless.channel", ""]
    assert app_module.get_wifi_radio() == "a:0"                    # nmcli reports channel 0 when unset


def test_refused_setting_reports_cleanly(app_module, monkeypatch, no_sleep):
    radio = Radio(refuse=True)
    monkeypatch.setattr(subprocess, "run", radio)
    msg, err = app_module.set_wifi_radio("a:36")
    assert msg is None and "refused" in err and not any(c[-2:] == ["up", "Gateway-AP"] for c in radio.cmds)


def test_disabled_hotspot_only_saves(app_module, monkeypatch, no_sleep):
    radio = Radio(active=False)
    monkeypatch.setattr(subprocess, "run", radio)
    msg, err = app_module.set_wifi_radio("a:40")
    assert "takes effect when you enable it" in msg and (radio.band, radio.channel) == ("a", "40")
    assert not any(c[-2:] == ["up", "Gateway-AP"] for c in radio.cmds)


def test_bad_and_unchanged_choices(app_module, monkeypatch, no_sleep):
    radio = Radio(band="a", channel="36")
    monkeypatch.setattr(subprocess, "run", radio)
    assert app_module.set_wifi_radio("a:52") == (None, "Unknown band/channel")     # DFS channel not offered
    assert app_module.set_wifi_radio("a:36") == ("Nothing to change.", None)
    assert not any("modify" in c for c in radio.cmds)


def test_get_wifi_radio_falls_back(app_module, monkeypatch):
    monkeypatch.setattr(subprocess, "run", Radio(band="", channel=""))
    assert app_module.get_wifi_radio() == "bg:0"
    monkeypatch.setattr(subprocess, "run", Radio(band="a", channel="99"))
    assert app_module.get_wifi_radio() == "bg:0"                                  # not one we offer


# Trimmed `iw list`: an EU-style domain where 149+ isn't allowed and 52 needs radar detection.
IW_LIST_EU = """\
Wiphy phy0
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412 MHz [1] (20.0 dBm)
\t\t\t* 2437 MHz [6] (20.0 dBm)
\t\t\t* 2462 MHz [11] (20.0 dBm)
\t\t\t* 2484 MHz [14] (disabled)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5180 MHz [36] (20.0 dBm)
\t\t\t* 5200 MHz [40] (20.0 dBm)
\t\t\t* 5260 MHz [52] (20.0 dBm) (no IR, radar detection)
\t\t\t* 5745 MHz [149] (disabled)
"""
# No country set: 5 GHz is passive-only ("no IR"), so no AP can start there.
IW_LIST_WORLD = IW_LIST_EU.replace("[36] (20.0 dBm)", "[36] (20.0 dBm) (no IR)").replace(
    "[40] (20.0 dBm)", "[40] (20.0 dBm) (no IR)")


def test_radio_choices_follow_regulatory_domain(app_module, monkeypatch):
    monkeypatch.setattr(subprocess, "run", FakeRun([(["iw", "list"], IW_LIST_EU)]))
    choices = app_module.wifi_radio_choices("bg:0")
    assert {"bg:0", "bg:1", "bg:6", "bg:11", "a:0", "a:36", "a:40"} <= set(choices)
    assert not {"a:44", "a:149", "a:165"} & set(choices)                     # not listed / not allowed here

    monkeypatch.setattr(subprocess, "run", FakeRun([(["iw", "list"], IW_LIST_WORLD)]))
    choices = app_module.wifi_radio_choices("bg:0")
    assert not [k for k in choices if k.startswith("a:")]                    # no 5 GHz at all, not even "automatic"
    assert "a:149" in app_module.wifi_radio_choices("a:149")                 # the current setting is always shown


def test_radio_choices_fail_open(app_module, monkeypatch):
    monkeypatch.setattr(subprocess, "run", FakeRun([(["iw", "list"], "")]))
    assert app_module.wifi_radio_choices() is app_module.WIFI_RADIO_CHOICES

    def broken(*args, **kwargs):
        raise FileNotFoundError("iw")
    monkeypatch.setattr(subprocess, "run", broken)
    assert app_module.wifi_radio_choices() is app_module.WIFI_RADIO_CHOICES


# --- page ----------------------------------------------------------------------------

def test_page_has_theme_toast_radio_and_qr(app_module, monkeypatch, tmp_path):
    html = render_page(app_module, monkeypatch, message="Saved.")
    check_page(html, tmp_path)
    assert html.index('document.documentElement.setAttribute("data-theme"') < html.index("<style>")  # before paint
    assert 'id="theme-select"' in html and '[data-theme="dark"] body' in html
    assert 'class="msg msg-info" role="status"' in html
    assert 'action="/wifi/radio"' in html and '<option value="bg:0" selected>2.4 GHz, automatic channel</option>' in html
    assert "5 GHz, channel 52" not in html                                         # DFS channels aren't offered
    assert 'id="wifi-qr-toggle"' in html
