"""Drift guards between files that must agree with each other. This project
has been bitten by exactly this before: the installer and the live app
silently diverged for a whole round of changes."""
import re

from conftest import PACKAGE, ROOT

INSTALL = (PACKAGE / "install.sh").read_text(encoding="utf-8")
DEPLOY = (ROOT / "deploy.sh").read_text(encoding="utf-8")
GUIDE = (ROOT / "docs" / "build_guide.py").read_text(encoding="utf-8")


def install_sh_files():
    # install -m MODE -o OWNER -g GROUP "$SCRIPT_DIR/<src>" <dest>
    pattern = r'install -m (\d+) -o (\S+) -g (\S+) "\$SCRIPT_DIR/([^"]+)" (\S+)'
    return {src: (dest, mode, f"{owner}:{group}") for mode, owner, group, src, dest in re.findall(pattern, INSTALL)}


def deploy_sh_files():
    block = DEPLOY[DEPLOY.index("MANIFEST=(") : DEPLOY.index("\n)\n", DEPLOY.index("MANIFEST=("))]
    entries = re.findall(r'"([^"|]+)\|([^|]+)\|(\d+)\|([^|]+)\|[^"]*"', block)
    return {src: (dest, mode, owner) for src, dest, mode, owner in entries}


def test_every_installed_file_exists_in_package():
    for src in install_sh_files():
        assert (PACKAGE / src).is_file(), f"install.sh installs a missing file: {src}"


def test_deploy_manifest_matches_install_sh():
    installed = install_sh_files()
    deployed = {src.removeprefix("package/"): v for src, v in deploy_sh_files().items() if not src.startswith("@")}
    assert set(deployed) == set(installed), (
        f"only in install.sh: {sorted(set(installed) - set(deployed))}; "
        f"only in deploy.sh: {sorted(set(deployed) - set(installed))}")
    for src, spec in installed.items():
        assert deployed[src] == spec, f"{src}: install.sh {spec} vs deploy.sh {deployed[src]}"


def test_every_package_module_is_deployed():
    deployed = {src.removeprefix("package/") for src in deploy_sh_files()}
    for py in PACKAGE.glob("*.py"):
        assert py.name in deployed, f"package/{py.name} is never deployed"


def test_templates_tree_is_installed_and_deployed():
    # Both ship the whole package/templates tree rather than listing files.
    assert "find templates -type f" in INSTALL and 'install -D -m 640 -o root -g redsocks "$SCRIPT_DIR/$f"' in INSTALL
    assert "find templates -type f" in DEPLOY and '"package/$f|/opt/rasp-proxy-admin/$f|640|root:redsocks' in DEPLOY
    assert (PACKAGE / "templates" / "admin.html").is_file()
    pages = {p.stem for p in (PACKAGE / "templates" / "pages").glob("*.html")}
    admin = (PACKAGE / "templates" / "admin.html").read_text(encoding="utf-8")
    assert pages and all(f'{{% include "pages/{p}.html" %}}' in admin for p in pages)


def test_version_json_written_the_same_way():
    fmt = r"""printf '{"version": "%s", "date": "%s"}\n'"""
    assert fmt in INSTALL and fmt in DEPLOY


def normalise_sudoers(line):
    return (line.replace("$AP_CONN_NAME", "Gateway-AP").replace("$AP_IFACE", "wlan0")
            .replace("$u", "admin").strip())


def test_guide_documents_the_installers_sudoers_rules():
    installer = {normalise_sudoers(m) for m in re.findall(r'echo "(proxyadmin-svc ALL=\(root\) NOPASSWD: [^"]+)"', INSTALL)}
    guide = {m.strip() for m in re.findall(r"'(proxyadmin-svc ALL=\(root\) NOPASSWD: [^'\\]+)", GUIDE)}
    assert installer and installer == guide, (
        f"only in install.sh: {sorted(installer - guide)}; only in the guide: {sorted(guide - installer)}")


def test_help_page_license_matches_license_file():
    help_page = (PACKAGE / "templates" / "pages" / "help.html").read_text(encoding="utf-8")
    shown = re.search(r'<pre class="license-text">(.*?)</pre>', help_page, re.S).group(1)
    license_file = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert shown.strip() == license_file.strip(), "the Help page's license text differs from LICENSE"
    holder = re.search(r"^Copyright \(c\) \d{4} (.+)$", license_file, re.M).group(1)
    assert f"by {holder}." in help_page                                     # the About credit names the same author
