"""
Shared test setup. Everything here runs off the Pi: every OS-boundary call
(subprocess: nmcli/iptables/ipset/iw/sudo; /proc and /sys files; sockets)
is faked, so these tests prove logic, templates and inline JS -- never real
hardware behaviour.
"""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "package"
sys.path.insert(0, str(PACKAGE))
os.environ.setdefault("RASP_PROXY_ADMIN_USERS", "admin")


def load_script(filename, module_name):
    """Import a hyphen-named script from package/ (e.g. rasp-proxy-health.py)."""
    spec = importlib.util.spec_from_file_location(module_name, PACKAGE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeRun:
    """Stands in for subprocess.run: records every call and answers from
    `responses`, a list of (argv-prefix, stdout[, returncode]) tried in order."""

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, cmd, *args, **kwargs):
        self.calls.append({"cmd": list(cmd), "input": kwargs.get("input")})
        for response in self.responses:
            prefix, out = response[0], response[1]
            code = response[2] if len(response) > 2 else 0
            if list(cmd[:len(prefix)]) == list(prefix):
                return subprocess.CompletedProcess(cmd, code, out, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def commands(self, first=None):
        return [c["cmd"] for c in self.calls if first is None or c["cmd"][0] == first]


@pytest.fixture
def fake_run(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


@pytest.fixture(scope="session")
def app_module():
    import app

    return app


SAMPLE_PROFILES = {
    "Remote Proxy": {"description": "Abroad", "type": "http-connect", "ip": "203.0.113.10", "port": "8080",
                      "login": "u", "password": "p", "local_port": 20000},
    "Backup Proxy": {"description": "Testing", "type": "http-connect", "ip": "5.6.7.8", "port": "8888",
                "login": "", "password": "", "local_port": 20001},
}


def sample_rules():
    return [
        {"id": "r1", "pattern": "*skycdn-it.akamaized.net", "mode": "wildcard", "action": "Remote Proxy",
         "description": "TV8 live", "enabled": True},
        {"id": "r2", "pattern": "*.netrw.it", "mode": "wildcard", "action": "Remote Proxy",
         "description": "", "enabled": False},
    ]
