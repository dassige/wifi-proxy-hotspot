# Wi-Fi Proxy Hotspot — installable package

Turns a Debian 12+ / Raspberry Pi OS (Bookworm or later) box with NetworkManager
into a Wi-Fi hotspot with a configurable **default** for every connected
device's TCP traffic — direct, or through any one of several saved upstream
proxy profiles — overridden for an internal network range you choose (always
direct) and for specific domains you list via routing rules (exact match,
wildcard, or regex, each sent direct or through any saved proxy, independent
of the default and of each other). Every saved proxy profile stays reachable
simultaneously — there is no single "active" proxy to switch, each rule and
the default simply name which one they want. A small PAM-authenticated web
panel (your existing Linux login, no separate account) manages all of it —
the default, the proxy profiles (add/edit/delete), the Wi-Fi network (including
a one-click restart and a separate on/off switch for the hotspot itself), the
bypass range, and the pattern rules (each individually enable/disable-able
without deleting it) — with no command line needed afterwards. A separate
one-click reboot restarts the whole box. The panel is laid out as a set of
pages behind a left-hand menu rather than one long scrolling form. The
Devices page lists every device that has ever joined, not just the currently
connected ones, with live Sent/Received traffic (counted directly by the
firewall, no packet capture, negligible CPU, refreshed automatically every
few seconds) and a Block/Unblock control per device that survives it going
offline. Every section has a small (?) help icon with concrete examples, and
the whole configuration (proxy profiles, pattern rules, bypass range) can be
exported to a file and re-imported, e.g. before a risky change or to clone
the setup onto another box. A Help page at the end of the menu links to the
full admin/user guide as a PDF, deployed onto the box at install time so it
opens even without internet access, and shows the exact version and build
date installed (read from `pyproject.toml` at install time, so it can never
drift from what's actually running).

Built and live-tested on a Raspberry Pi 3B+ (Debian 13 Trixie); see the
[main README](../README.md) for hardware notes. See
`../docs/Wi-Fi-Proxy-Hotspot-Guide.pdf` for full background, architecture,
troubleshooting, and the user-facing "how do I connect a device" guide.

## Requirements

- Debian 12+ or Raspberry Pi OS Bookworm/Trixie or later, with NetworkManager
  (`nmcli` must exist). Older images using `dhcpcd`/`hostapd`/`dnsmasq`
  directly (e.g. Raspberry Pi OS Legacy/Bullseye) are **not** supported by
  this script as-is — see the guide's Notes section for the manual equivalent.
- A wired interface (e.g. `eth0`) already connected to your internal network,
  even via DHCP — the installer converts it to a static IP.
- A wireless interface (e.g. `wlan0`) free to become the hotspot's radio. If
  it's currently a Wi-Fi client of another network, the installer will take
  it over — it cannot be a client and a hotspot at the same time on most
  hardware.
- The Wi-Fi country (regulatory domain) set, so the radio is allowed to
  transmit: `sudo raspi-config nonint do_wifi_country XX` on Raspberry Pi OS
  (`XX` = your two-letter country code), `sudo iw reg set XX` elsewhere. Then
  `rfkill list` should show the Wi-Fi radio unblocked.
- Root access on the box (run everything via `sudo`).
- The upstream proxy's address, port, and credentials (if any) to hand.

## Install

Get the whole repository onto the target machine (not just `package/`:
`install.sh` reads the version and build date from `../pyproject.toml` and
refuses to install without it), then run the installer from this folder:

```bash
git clone https://github.com/dassige/wifi-proxy-hotspot.git
cd wifi-proxy-hotspot/package
sudo ./install.sh
```

It will interactively ask for:
- the static IP/gateway/DNS for your wired interface,
- the hotspot's SSID and passphrase (leave passphrase blank to auto-generate),
- the internal CIDR that should bypass the proxy,
- the upstream proxy's type/address/port/credentials,
- which Linux username(s) may log into the admin web panel.

**If you're connected over SSH via the same wired interface being given a new
static IP, your session will drop partway through — that's expected. Wait a
few seconds and reconnect on the new address.**

At the end it prints the hotspot SSID/passphrase and the admin panel URL
(`https://<static-ip>:8443/`, self-signed certificate — your browser will warn,
that's expected).

## What it sets up

| Component | Purpose |
|---|---|
| Static IP (`nmcli`) | Fixed address on the wired interface |
| NetworkManager hotspot (`Gateway-AP`) | Wi-Fi AP, DHCP, NAT — all handled natively by NetworkManager |
| `redsocks` | One instance, one `redsocks{}` block per saved proxy profile, each on its own permanent local port — all reachable simultaneously |
| `redsocks-patches/` | Two small source patches applied on top of the stock Debian package (built from source, original binary backed up), fixing real per-connection latency: preemptive Basic auth instead of waiting for a 407, and `TCP_NODELAY` on the relay sockets. Best-effort at install time — see `redsocks-patches/README.md` |
| `iptables` `REDSOCKS` chain | Bypass CIDR (always direct) → pattern-rule overrides in order, each to its own profile's port or direct → configurable global default (direct, or a named profile) |
| `rasp-proxy-dns-router` (systemd, `CAP_NET_ADMIN` + `CAP_NET_RAW`) | Sits between the hotspot's dnsmasq and the internet; tags resolved IPs into per-rule `ipset`s so the firewall can route by domain pattern. Also passively captures devices' DNS queries on the AP interface for the panel's DNS Lookups page (in memory, snapshotted to `/run/rasp-proxy-dns/lookups.json`) |
| `rasp-proxy-firewall-init` (systemd, runs once at boot) | Rebuilds the whole REDSOCKS chain and its ipsets from scratch on every boot — `ipset` contents are never persisted by `netfilter-persistent`, so without this a saved rule referencing a since-vanished ipset silently fails the *entire* saved ruleset restore on reboot, leaving hotspot traffic completely unfiltered |
| Leak guards (`WPXDNS` nat, `WPXGUARD` filter, `WPXGUARD6` ip6tables; rebuilt by `rasp-proxy-rebuild-firewall`) | Force hotspot DNS (redirect outside port-53 lookups to dnsmasq, reject DNS-over-TLS on 853) and block forwarded IPv6, so devices can't route around the pattern rules. `dns_router.py` adds NXDOMAIN for iCloud Private Relay and Firefox's DoH canary. Each switchable on the Routing Rules page |
| `rasp-proxy-health.timer` (systemd, every 2 min, root oneshot) | Health checks behind the panel's Overview page (services, hotspot, firewall chains, DNS, proxies, power/temperature/disk/memory), plus email alerts on changes configured on the System page. Reports only |
| `rasp-proxy-admin` (systemd + gunicorn + Flask) | The admin web panel, bound only to the wired interface |
| `proxyadmin-svc` / `rasp-proxy-dns` (unprivileged system accounts) | Run the web panel and the DNS router respectively — neither runs as root |
| `iptables` `mangle` `WPXACCT_UP` / `WPXACCT_DOWN` chains | One cheap kernel counter per connected device (matched by IP), hooked from `PREROUTING`/`POSTROUTING` so both direct and proxied traffic are counted the same way; kept in sync with the current device list on every panel page load, deliberately not persisted across reboots (these are live session stats, not policy) |
| `/var/lib/rasp-proxy-admin/proxies.json` | Saved proxy profiles (name, description, type, address, credentials, permanent local port) |
| `/var/lib/rasp-proxy-admin/pattern_rules.json` | The internal bypass CIDR, the global default (direct or a profile name), and ordered routing rules (pattern, mode, action, description, enabled) — the single source of truth the firewall is rebuilt from |
| `/var/lib/rasp-proxy-admin/devices.json` | Every device ever seen (MAC, hostname, first/last seen, blocked) — kept so a blocked or offline device stays visible and unblockable, unlike the live association list alone |
| `/opt/rasp-proxy-admin/Wi-Fi-Proxy-Hotspot-Guide.pdf` | The full admin/user guide, deployed alongside the app itself and served by the panel's Help page |
| `RASP_PROXY_VERSION` / `RASP_PROXY_VERSION_DATE` (systemd unit env vars) | The version/build date shown on the Help page — parsed fresh out of `pyproject.toml` by `install.sh` at install time, never from a copy that could go stale |
| Hotspot MAC denylist (`802-11-wireless.mac-address-denylist` on the `Gateway-AP` connection) | Enforces per-device Block/Unblock; kept in sync with devices.json and applied by reactivating the connection |
| Three root-owned helper scripts + a narrow sudoers file | The only things the web panel can do as root: check a PAM login, restart redsocks, modify the one named hotspot connection (including its MAC denylist), bring it up or down (hotspot enable/disable), read the lease file, rebuild the firewall chain, reboot the box (via a delayed transient systemd timer so the request can finish first), sync the per-device traffic-accounting chains |

## Uninstall

```bash
sudo ./uninstall.sh
```

Removes the admin panel, its service account and sudoers rule, the redsocks
config and firewall rules, and the hotspot connection. Leaves the wired
interface's static IP and the installed packages in place (see the script's
own output for exactly what to revert manually if you want a full teardown).

## Files

| File | Purpose |
|---|---|
| `install.sh` | Interactive installer — run this |
| `uninstall.sh` | Removes everything the installer created |
| `app.py` | The admin web panel (Flask) |
| `dns_router.py` | The DNS pattern-router daemon (runs as `rasp-proxy-dns`) |
| `pattern_match.py` | Hostname-vs-rule matching shared by `dns_router.py` and `app.py`, so the tagging and the DNS Lookups page can never disagree |
| `proxy_check.py` | Direct proxy-profile check (connect/auth/TLS timings) and exit-IP lookup, shared by the panel's Check button and the health check; also opens the tunnels `proxy_doh.py` uses |
| `proxy_doh.py` | DNS-over-HTTPS through a proxy (warm tunnel pool per proxy): `dns_router.py` uses it for proxied rules' hostnames, so CDNs answer with servers near the proxy |
| `mailer.py` | Email alert settings (`alerts.json`, 0600) and SMTP sending, shared by the panel and the health check |
| `help_texts.py` | The panel's (?) help texts (HTML fragments) |
| `templates/` | The panel's Jinja templates: `admin.html` (layout and page script), `admin.css`, `macros.html`, and `pages/<page>.html`, one per menu page |
| `rasp-proxy-health.py` | Root health check, run every 2 minutes by `rasp-proxy-health.timer`: writes the Overview page's status and sends email alerts on changes. Alert-only, never changes routing |
| `rasp-proxy-pamcheck.py` | Root-owned helper: checks a Linux login via PAM |
| `rasp-proxy-rebuild-firewall.py` | Root-owned helper: rebuilds the whole firewall chain (bypass CIDR + pattern rules + catch-all) |
| `rasp-proxy-traffic-sync.py` | Root-owned helper: keeps the per-device traffic-accounting chains in sync with the current connected-device list |
| `pam-service` | PAM stack used for the admin panel's login (`/etc/pam.d/rasp-proxy-admin`) |
| `Wi-Fi-Proxy-Hotspot-Guide.pdf` | The admin/user guide, deployed onto the box and served by the panel's Help page — a synced copy of `../docs/Wi-Fi-Proxy-Hotspot-Guide.pdf`, regenerated by `docs/build_guide.py` |
