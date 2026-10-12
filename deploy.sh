#!/bin/bash
# ==============================================================================
# Wi-Fi Proxy Hotspot — deploy code changes to an already-installed box
# ==============================================================================
# Does, in one command, what every manual deploy on this project has done:
#   1. pre-flight: compile-check every Python file, syntax-check every shell
#      script
#   2. compare each deployable file's SHA-256 with the copy on the box, so
#      only files that actually changed are touched
#   3. upload them, keep the previous copy as <file>.bak-deploy, install with
#      the right owner/mode, and verify the installed hash byte-for-byte
#   4. restart only the services whose files changed
#   5. post-check: services active, no new warnings in their journals, and a
#      fresh health-check run (the Overview page's data)
#
# It deploys code only. It does NOT change systemd units (except the
# redsocks drop-in below), sudoers, NetworkManager settings or the state
# under /var/lib: those are install-time configuration (see
# package/install.sh), changed deliberately and by hand when they need to be.
#
# Usage:
#   ./deploy.sh              show what would change, ask, then deploy
#   ./deploy.sh --dry-run    only show what would change
#   ./deploy.sh --yes        deploy without asking (non-interactive use)
# Options: --host <ssh host alias> (default rasp-proxy),
#          --ssh-config <file>     (default keys/ssh_config)
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
HOST="rasp-proxy"
SSH_CONFIG="$ROOT/keys/ssh_config"
DRY_RUN=0
ASSUME_YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --host) HOST="$2"; shift ;;
        --ssh-config) SSH_CONFIG="$2"; shift ;;
        -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done
[ -f "$SSH_CONFIG" ] || { echo "SSH config not found: $SSH_CONFIG" >&2; exit 2; }
SSH=(ssh -F "$SSH_CONFIG" -o BatchMode=yes "$HOST")
SCP=(scp -q -F "$SSH_CONFIG" -o BatchMode=yes)
# Whichever actually runs (on Windows, "python3" can be a Store stub that doesn't).
PY=""
for candidate in python3 python; do
    if "$candidate" -c "import sys" >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[ -n "$PY" ] || { echo "Python is needed for the pre-flight checks." >&2; exit 2; }

# source (relative to the repo, or @generated) | destination | mode | owner:group | restart
MANIFEST=(
    "package/app.py|/opt/rasp-proxy-admin/app.py|640|root:redsocks|rasp-proxy-admin"
    "package/dns_router.py|/opt/rasp-proxy-admin/dns_router.py|640|root:redsocks|rasp-proxy-dns-router"
    "package/pattern_match.py|/opt/rasp-proxy-admin/pattern_match.py|640|root:redsocks|rasp-proxy-admin rasp-proxy-dns-router"
    "package/proxy_check.py|/opt/rasp-proxy-admin/proxy_check.py|640|root:redsocks|rasp-proxy-admin rasp-proxy-dns-router"
    "package/proxy_doh.py|/opt/rasp-proxy-admin/proxy_doh.py|640|root:redsocks|rasp-proxy-dns-router"
    "package/mailer.py|/opt/rasp-proxy-admin/mailer.py|640|root:redsocks|rasp-proxy-admin"
    "package/help_texts.py|/opt/rasp-proxy-admin/help_texts.py|640|root:redsocks|rasp-proxy-admin"
    "@version.json|/opt/rasp-proxy-admin/version.json|640|root:redsocks|rasp-proxy-admin"
    "package/Wi-Fi-Proxy-Hotspot-Guide.pdf|/opt/rasp-proxy-admin/Wi-Fi-Proxy-Hotspot-Guide.pdf|640|root:redsocks|"
    "package/rasp-proxy-pamcheck.py|/usr/local/sbin/rasp-proxy-pamcheck|750|root:root|"
    "package/rasp-proxy-rebuild-firewall.py|/usr/local/sbin/rasp-proxy-rebuild-firewall|750|root:root|"
    "package/rasp-proxy-traffic-sync.py|/usr/local/sbin/rasp-proxy-traffic-sync|750|root:root|"
    "package/rasp-proxy-health.py|/usr/local/sbin/rasp-proxy-health|750|root:root|"
    "package/pam-service|/etc/pam.d/rasp-proxy-admin|644|root:root|"
    "package/redsocks-override.conf|/etc/systemd/system/redsocks.service.d/override.conf|644|root:root|@daemon-reload"
)

# Every file under package/templates (the panel's Jinja templates), however
# many there are; Flask caches templates, so they need an admin restart too.
while IFS= read -r f; do
    MANIFEST+=("package/$f|/opt/rasp-proxy-admin/$f|640|root:redsocks|rasp-proxy-admin")
done < <(cd "$ROOT/package" && find templates -type f | sort)

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "== Pre-flight checks =="
# Relative paths from the repo root: Windows Python can't open Git Bash's /c/... paths.
cd "$ROOT"
for f in package/*.py; do
    "$PY" -m py_compile "$f" || { echo "py_compile failed: $f" >&2; exit 1; }
done
for f in package/*.sh deploy.sh; do
    bash -n "$f" || { echo "bash -n failed: $f" >&2; exit 1; }
done
if [ -d tests ]; then
    "$PY" -c "import pytest, flask, dns" 2>/dev/null \
        || { echo "The tests need pytest, flask and dnspython: pip install pytest flask dnspython" >&2; exit 1; }
    "$PY" -m pytest -q tests || { echo "Tests failed; not deploying." >&2; exit 1; }
fi
echo "  OK"

# version.json from pyproject.toml, exactly as install.sh writes it.
VERSION="$(grep -m1 -E '^version = ' "$ROOT/pyproject.toml" | sed -E 's/^version = "(.*)"$/\1/')"
VERSION_DATE="$(grep -m1 -E '^versionDate = ' "$ROOT/pyproject.toml" | sed -E 's/^versionDate = "(.*)"$/\1/')"
[ -n "$VERSION" ] && [ -n "$VERSION_DATE" ] || { echo "Couldn't read version from pyproject.toml" >&2; exit 1; }
printf '{"version": "%s", "date": "%s"}\n' "$VERSION" "$VERSION_DATE" > "$STAGE/version.json"

src_path() { case "$1" in @*) echo "$STAGE/${1#@}" ;; *) echo "$ROOT/$1" ;; esac; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

DESTS=()
for entry in "${MANIFEST[@]}"; do
    IFS='|' read -r src dst _ _ _ <<< "$entry"
    [ -f "$(src_path "$src")" ] || { echo "Missing source file: $src" >&2; exit 1; }
    DESTS+=("$dst")
done

echo "== Comparing with $HOST (version $VERSION, $VERSION_DATE) =="
REMOTE_HASHES="$("${SSH[@]}" "sudo -n sha256sum ${DESTS[*]} 2>/dev/null || true")"

CHANGED=()
for entry in "${MANIFEST[@]}"; do
    IFS='|' read -r src dst mode owner restart <<< "$entry"
    local_hash="$(sha "$(src_path "$src")")"
    remote_hash="$(printf '%s\n' "$REMOTE_HASHES" | awk -v d="$dst" '$2 == d {print $1}')"
    if [ -z "$remote_hash" ]; then
        state="NEW"
    elif [ "$remote_hash" != "$local_hash" ]; then
        state="CHANGED"
    else
        state="same"
    fi
    printf '  %-8s %s\n' "$state" "$dst"
    [ "$state" = "same" ] || CHANGED+=("$entry|$local_hash")
done

if [ ${#CHANGED[@]} -eq 0 ]; then
    echo "Nothing to deploy: the box already matches this checkout."
    exit 0
fi

RESTARTS=()
DAEMON_RELOAD=0
for entry in "${CHANGED[@]}"; do
    IFS='|' read -r _ _ _ _ restart _ <<< "$entry"
    for svc in $restart; do
        if [ "$svc" = "@daemon-reload" ]; then
            DAEMON_RELOAD=1
        elif [[ " ${RESTARTS[*]:-} " != *" $svc "* ]]; then
            RESTARTS+=("$svc")
        fi
    done
done
echo "== Plan =="
echo "  install ${#CHANGED[@]} file(s)"
[ $DAEMON_RELOAD -eq 1 ] && echo "  systemctl daemon-reload (the redsocks drop-in takes effect at redsocks' next start; redsocks isn't restarted)"
if [ ${#RESTARTS[@]} -gt 0 ]; then
    echo "  restart: ${RESTARTS[*]}"
else
    echo "  no service restarts needed"
fi

if [ $DRY_RUN -eq 1 ]; then
    echo "Dry run: nothing changed."
    exit 0
fi
if [ $ASSUME_YES -ne 1 ]; then
    if [ ! -t 0 ]; then
        echo "Not a terminal and --yes not given: stopping before any change." >&2
        exit 1
    fi
    read -r -p "Deploy these changes to $HOST now? [y/N] " answer
    [ "${answer,,}" = "y" ] || { echo "Aborted: nothing changed."; exit 0; }
fi

# Stage the changed files under neutral names, plus the script that installs
# them on the box, and upload everything in one go.
REMOTE_DIR="/tmp/wpx-deploy-$$-$RANDOM"
mkdir -p "$STAGE/upload"
{
    echo 'set -euo pipefail'
    echo "D=$REMOTE_DIR"
    cat <<'EOS'
install_one() {
    local src="$1" dst="$2" mode="$3" owner="$4" want="$5"
    sudo -n mkdir -p "$(dirname "$dst")"
    if sudo -n test -f "$dst"; then sudo -n cp -p "$dst" "$dst.bak-deploy"; fi
    sudo -n install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$D/$src" "$dst"
    local got
    got="$(sudo -n sha256sum "$dst" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then echo "  HASH MISMATCH after install: $dst" >&2; exit 1; fi
    echo "  installed $dst (verified)"
}
EOS
} > "$STAGE/upload/apply.sh"
i=0
for entry in "${CHANGED[@]}"; do
    IFS='|' read -r src dst mode owner _ hash <<< "$entry"
    cp "$(src_path "$src")" "$STAGE/upload/f$i"
    printf 'install_one f%d %q %s %s %s\n' "$i" "$dst" "$mode" "$owner" "$hash" >> "$STAGE/upload/apply.sh"
    i=$((i + 1))
done
{
    [ $DAEMON_RELOAD -eq 1 ] && echo 'sudo -n systemctl daemon-reload && echo "  systemctl daemon-reload"'
    for svc in "${RESTARTS[@]:-}"; do
        [ -n "$svc" ] && echo "sudo -n systemctl restart $svc && echo '  restarted $svc'"
    done
    # Warnings count only from here: a restart kills in-flight requests (e.g.
    # an open panel's traffic poll mid-sudo), which logs harmless noise.
    echo 'sleep 1; T0="$(date "+%Y-%m-%d %H:%M:%S")"'
    # A restarted DNS router needs ~10s for its first snapshot (capture
    # status) and its Proxied Lookups tunnels; checking sooner reports
    # startup as warnings.
    if [[ " ${RESTARTS[*]:-} " == *" rasp-proxy-dns-router "* ]]; then echo 'sleep 12'; else echo 'sleep 4'; fi
    cat <<'EOS'
echo "== Post-checks =="
bad=0
for svc in redsocks rasp-proxy-dns-router rasp-proxy-admin rasp-proxy-health.timer; do
    state="$(systemctl is-active "$svc" || true)"
    printf '  %-26s %s\n' "$svc" "$state"
    [ "$state" = "active" ] || bad=1
done
warnings="$(sudo -n journalctl -u rasp-proxy-admin -u rasp-proxy-dns-router --since "$T0" --no-pager -p warning -o cat 2>/dev/null || true)"
if [ -n "$warnings" ]; then echo "  new warnings in the journal:"; printf '%s\n' "$warnings" | tail -10 | sed 's/^/    /'; bad=1; fi
if sudo -n systemctl start rasp-proxy-health.service; then
    # A red health check fails the deploy (amber is reported, not fatal).
    sudo -n python3 - <<'PY' || bad=1
import json
s = json.load(open("/run/rasp-proxy-health/status.json"))
print(f"  health check: overall {s['overall']}")
for c in s["checks"]:
    if c["status"] not in ("ok", "off"):
        print(f"    {c['status']:<4} {c['label']}: {c['detail']}")
raise SystemExit(1 if s["overall"] == "fail" else 0)
PY
else
    echo "  health check didn't run"; bad=1
fi
exit $bad
EOS
} >> "$STAGE/upload/apply.sh"

echo "== Deploying to $HOST =="
"${SSH[@]}" "mkdir -p $REMOTE_DIR"
"${SCP[@]}" "$STAGE"/upload/* "$HOST:$REMOTE_DIR/"
set +e
"${SSH[@]}" "bash $REMOTE_DIR/apply.sh"
status=$?
set -e
"${SSH[@]}" "rm -rf $REMOTE_DIR" || true
if [ $status -eq 0 ]; then
    echo "Deployed version $VERSION: all checks passed."
else
    echo "Deploy finished with problems (see above). Previous copies are kept as <file>.bak-deploy on the box." >&2
fi
exit $status
