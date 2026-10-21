"""
Email alerts: the SMTP settings file and sending, shared by app.py (the
System page's Email Alerts settings and "Send test email") and
rasp-proxy-health (which sends the real alerts). Stdlib-only.

The settings file holds the SMTP password, so it is written 0600 and the
password is never returned to the browser or included in any error text.
"""
import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

ALERTS_FILE = "/var/lib/rasp-proxy-admin/alerts.json"
SECURITY_MODES = ("starttls", "ssl", "none")
DEFAULTS = {
    "enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "security": "starttls",
    "username": "",
    "password": "",
    "sender": "",
    "recipients": "",
    "notify_boot": True,
    # Limits on how many emails a flapping check can cause (rasp-proxy-health).
    "recover_after_min": 10,
    "min_interval_min": 30,
}
LIMITS = {"recover_after_min": 240, "min_interval_min": 1440}


def load_alerts_config():
    config = dict(DEFAULTS)
    try:
        with open(ALERTS_FILE) as f:
            config.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return config


def alert_limit(config, key):
    """One of the LIMITS settings as whole minutes, clamped to its range. An
    imported or hand-edited file can hold anything, so bad values fall back to
    the default rather than breaking the health check."""
    try:
        value = int(config.get(key, DEFAULTS[key]))
    except (TypeError, ValueError):
        value = DEFAULTS[key]
    return min(max(value, 0), LIMITS[key])


def save_alerts_config(config):
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    tmp = ALERTS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({k: config.get(k, v) for k, v in DEFAULTS.items()}, f, indent=2)
    os.replace(tmp, ALERTS_FILE)


def recipient_list(config):
    return [r.strip() for r in config.get("recipients", "").replace(";", ",").split(",") if r.strip()]


def is_configured(config):
    return bool(config.get("smtp_host") and recipient_list(config))


def send_email(config, subject, body, timeout=20):
    """Sends one plain-text email. Returns None on success, else a short
    error string (never containing the password)."""
    recipients = recipient_list(config)
    if not config.get("smtp_host") or not recipients:
        return "Email alerts aren't configured (SMTP server and at least one recipient are required)."
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.get("sender") or config.get("username") or f"rasp-proxy@{config['smtp_host']}"
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="rasp-proxy.local")
    msg.set_content(body)
    try:
        host, port = config["smtp_host"], int(config.get("smtp_port") or 0)
        ctx = ssl.create_default_context()
        if config.get("security") == "ssl":
            server = smtplib.SMTP_SSL(host, port or 465, timeout=timeout, context=ctx)
        else:
            server = smtplib.SMTP(host, port or 587, timeout=timeout)
        with server:
            if config.get("security") == "starttls":
                server.starttls(context=ctx)
            if config.get("username"):
                server.login(config["username"], config.get("password", ""))
            server.send_message(msg)
        return None
    except smtplib.SMTPAuthenticationError as e:
        return f"SMTP login rejected ({e.smtp_code}). Check the username and password (Gmail needs an app password)."
    except Exception as e:
        text = str(e).replace(config.get("password") or "\0", "***") if config.get("password") else str(e)
        return f"{type(e).__name__}: {text}"[:200]
