import os
import smtplib
import stat
import sys

import pytest

import mailer

CONFIG = dict(mailer.DEFAULTS, enabled=True, smtp_host="smtp.example.com", smtp_port=587, security="starttls",
              username="me@example.com", password="app-pass-123", recipients="a@b.com; c@d.org")


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg):
        self.calls.append(("send", msg["To"], msg["Subject"]))


@pytest.fixture(autouse=True)
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)


def test_starttls_login_and_send():
    assert mailer.send_email(CONFIG, "subj", "body") is None
    s = FakeSMTP.instances[0]
    assert (s.host, s.port) == ("smtp.example.com", 587)
    assert s.calls == ["starttls", ("login", "me@example.com", "app-pass-123"), ("send", "a@b.com, c@d.org", "subj")]


def test_ssl_mode_skips_starttls_and_default_port():
    mailer.send_email(dict(CONFIG, security="ssl", smtp_port=0), "s", "b")
    s = FakeSMTP.instances[0]
    assert s.port == 465 and "starttls" not in s.calls


def test_not_configured():
    assert mailer.send_email(dict(mailer.DEFAULTS), "s", "b").startswith("Email alerts aren't configured")


def test_errors_never_contain_the_password(monkeypatch):
    def boom(self, user, password):
        raise smtplib.SMTPException(f"server said: bad credentials for {password}")

    monkeypatch.setattr(FakeSMTP, "login", boom)
    error = mailer.send_email(CONFIG, "s", "b")
    assert "app-pass-123" not in error and "***" in error

    def auth_fail(self, user, password):
        raise smtplib.SMTPAuthenticationError(535, b"5.7.8 rejected")

    monkeypatch.setattr(FakeSMTP, "login", auth_fail)
    assert "app password" in mailer.send_email(CONFIG, "s", "b")


def test_settings_roundtrip_drops_unknown_keys(tmp_path, monkeypatch):
    path = tmp_path / "alerts.json"
    monkeypatch.setattr(mailer, "ALERTS_FILE", str(path))
    mailer.save_alerts_config(dict(CONFIG, junk="x"))
    back = mailer.load_alerts_config()
    assert back["smtp_host"] == "smtp.example.com" and "junk" not in back
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600        # holds the SMTP password
