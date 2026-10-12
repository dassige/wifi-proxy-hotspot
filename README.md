# Wi-Fi Proxy Hotspot

[![CI](https://github.com/dassige/wifi-proxy-hotspot/actions/workflows/ci.yml/badge.svg)](https://github.com/dassige/wifi-proxy-hotspot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Turn a Raspberry Pi (or any small Debian-based Linux box with Ethernet and
Wi-Fi) into a **Wi-Fi hotspot that sends chosen websites through an upstream
proxy**. Any device that joins the hotspot gets this without any setup: phones,
laptops, smart TVs, game consoles, streaming sticks. Everything else goes out
directly. You manage it all from a small web admin panel, with no command line
needed after the install.

> **Disclaimer:** this is a personal project shared as-is, without warranty,
> and it is **not regularly maintained**. See [Disclaimer](#disclaimer).

## Why

Many devices can't be configured to use a proxy at all, and many apps ignore
the system proxy setting. Even where it is possible, setting it up on every
device is tedious. This box does it once, at the network level:

- **Per-domain routing.** Send only `*.example-tv.com` through a proxy in
  another country, so the rest of your browsing keeps full speed and your
  local address.
- **Every device, zero configuration.** It is transparent: devices just join
  the Wi-Fi network.
- **Several proxies at once.** Different rules can use different proxies
  (HTTP CONNECT or SOCKS5), and devices can be pinned to one proxy or to
  "direct".
- **Your local network stays local.** An internal address range (printers,
  NAS, your router) is always reached directly.

Typical uses: watching your home country's streaming services while abroad (or
the reverse), testing geo-dependent websites, or giving a smart TV a proxied
connection it can't configure itself.

## Features

- **Routing rules:** exact host, wildcard (`*.example.com`) or regular
  expression, several patterns per rule, ordered, each sent direct or through
  any saved proxy, and each one can be switched on or off. Built-in presets and
  a rule tester ("where would this hostname go, and why?") are included.
- **Proxy profiles:** HTTP CONNECT and SOCKS5, with or without credentials,
  all usable at the same time. A **Check** button measures connect, auth, TLS
  and first-byte times separately and shows the proxy's exit IP and country.
- **A configurable default** for everything no rule matches: direct, or any
  proxy.
- **Proxied lookups:** hostnames that go through a proxy are also *resolved*
  through it (DNS-over-HTTPS), so video CDNs hand out servers near the proxy
  instead of near you. In one measurement, video segments through a proxy on
  another continent arrived about twice as fast.
- **Leak guards:** devices can't bypass the rules through their own DNS
  servers, DNS-over-TLS, iCloud Private Relay, Firefox's DoH canary or IPv6.
  Each guard can be switched off.
- **Devices page:** every device ever seen, with nickname, live traffic,
  Wi-Fi signal, Block/Unblock, and per-device routing (always direct, or always
  through a given proxy).
- **DNS Lookups page:** what each device is looking up, which rule matched it,
  and one-click "new rule" / "add to rule".
- **Overview and alerts:** health checks every 2 minutes (services, hotspot,
  firewall, DNS, every proxy, temperature, power, disk) and optional email
  alerts through your own SMTP server. Alerts only report; they never change
  routing.
- **Wi-Fi management:** SSID and passphrase, a join QR code, 2.4/5 GHz band and
  channel (only channels your country allows are offered), a hotspot on/off
  switch, and a restart button.
- **Backup & Restore:** export and import the whole configuration as one
  JSON file.
- **Help built in:** a (?) help icon on every section, plus the full PDF guide
  served by the box itself, so it works with no internet connection.
- **Mobile-friendly, with dark mode.** Login uses the box's own Linux
  accounts (PAM), so there are no separate passwords to manage.

## How it works

```
 phone / TV / laptop                         Raspberry Pi (or other Linux box)
 ───────────────────        Wi-Fi           ──────────────────────────────────────────────
                     ───── (wlan0) ──────►  NetworkManager hotspot (DHCP, NAT, dnsmasq)
                                               │ DNS queries
                                               ▼
                                            dns_router ── matches routing rules, tags the
                                               │           resolved IPs into per-rule ipsets
                                               ▼
                                            iptables (nat REDSOCKS chain):
                                              internal range ─────────────► direct
                                              rule N matches (ipset) ─────► direct or proxy X
                                              device pinned ─────────────► direct or proxy Y
                                              everything else ────────────► the default
                                               │
                                               ▼  proxied TCP
                                            redsocks (one local port per proxy profile)
                                               │
                                               ▼
                                            Ethernet (eth0) ──► upstream HTTP/SOCKS5 proxy ──► internet
```

The admin panel (Flask + gunicorn, HTTPS) listens only on the wired
interface's address. The firewall is rebuilt from
scratch from one JSON file on every change and on every boot, so a reboot
always brings it back in a consistent state. More detail is in the
[guide](docs/Wi-Fi-Proxy-Hotspot-Guide.pdf).

## Hardware and software

**Built and tested on a Raspberry Pi 3B+** running Debian 13 (Trixie) with
NetworkManager. That is the only configuration that has actually been tested.

Nothing in it is Raspberry Pi specific, apart from two optional health
readings (under-voltage and SoC temperature) that are simply skipped where
they aren't available. It should run on any Debian-based Linux box that has:

| Requirement | Notes |
|---|---|
| A Debian 12+ based OS with **NetworkManager** | Raspberry Pi OS Bookworm or later (Lite is enough), Debian 12/13, or similar. `nmcli` must exist. Older images using `dhcpcd`/`hostapd` are not supported by the installer. |
| A **wired Ethernet** interface | Connects the box to your router/internet, and serves the admin panel. The installer gives it a static IP. |
| A **Wi-Fi adapter that supports AP mode** | Check with `iw list`: "Supported interface modes" must include `AP`. The Pi 3B+'s built-in Wi-Fi works, and the Pi 4/5's uses the same driver family. Not every USB dongle supports AP mode. |
| ~1 GB RAM, a few hundred MB of disk | A Pi 3B+ (1 GB) runs it comfortably without a desktop. |
| A **good power supply** (on a Pi) | Under-voltage throttles the CPU and makes proxied traffic noticeably slow. Use the official PSU. |
| An **upstream proxy** | Any HTTP CONNECT or SOCKS5 proxy (address, port, and username/password if it needs them). This project doesn't provide one. |

Other likely-good hosts: Raspberry Pi 4/5, a Pi Zero 2 W with a USB Ethernet
adapter, or an x86 mini PC with an AP-capable Wi-Fi card. If you get it
running on other hardware, a note in the issues is welcome.

## Installation

The steps below assume a Raspberry Pi. On other hardware, step 1 is just "a
fresh Debian-based install with NetworkManager, reachable over SSH on
Ethernet".

### 1. Prepare the OS

1. Flash **Raspberry Pi OS Lite (64-bit)** with
   [Raspberry Pi Imager](https://www.raspberrypi.com/software/). In its
   settings, set a username and password and enable SSH. **Don't** configure a
   Wi-Fi network, because the Wi-Fi radio will become the hotspot.
2. Connect the Pi to your router **with an Ethernet cable**, boot it, and SSH
   in (find its address on your router's DHCP page).
3. Update it:

   ```bash
   sudo apt update && sudo apt full-upgrade -y && sudo reboot
   ```

### 2. Set the Wi-Fi country

The radio may only transmit on the channels your country allows, and on
Raspberry Pi OS it stays blocked until a country is set. Use your two-letter
country code (`GB`, `US`, `DE`, `IT`, `AU`, ...):

```bash
sudo raspi-config nonint do_wifi_country XX    # Raspberry Pi OS
# other distros: sudo iw reg set XX  (and make it persistent your distro's way)
sudo rfkill unblock wifi
iw reg get                                      # should show "country XX"
```

### 3. Run the installer

```bash
sudo apt install -y git tmux
git clone https://github.com/dassige/wifi-proxy-hotspot.git
cd wifi-proxy-hotspot/package
tmux                      # so the install survives if your SSH session drops
sudo ./install.sh
```

It asks for:

- the **static IP** for the wired interface (e.g. `192.168.1.10/24`), the
  gateway (your router, e.g. `192.168.1.1`) and DNS servers. Pick an address
  outside your router's DHCP range, or reserve it on the router;
- the hotspot's **SSID and passphrase** (leave the passphrase blank to
  generate one);
- the **internal range** that always bypasses the proxy (defaults to your LAN);
- your **first upstream proxy**: type (`http-connect` or `socks5`), address,
  port, and credentials;
- the **Linux user(s)** allowed to log into the admin panel.

> The first thing the installer does is apply the static IP to the Ethernet
> interface. If you're connected over SSH through it, your session may drop,
> for good if the address changes. That's why the commands above use `tmux`:
> reconnect to the new address and run `tmux attach` to pick up where the
> installer is. (Without tmux, a dropped session can stop the installer
> halfway.) Choosing the address the box already has avoids the drop
> entirely; reserve it on your router.

The installer also tries to build two small **redsocks performance patches**
from source (see [`package/redsocks-patches/`](package/redsocks-patches/)).
This step is optional: if it fails, the stock redsocks is kept and everything
still works.

At the end it prints the hotspot name, the passphrase and the admin panel
address.

### 4. Log into the admin panel

Open `https://<static-ip>:8443/` from a computer on your **wired/home
network** (not from the hotspot). The certificate is self-signed, so the
browser warns once. Log in with the Linux username and password you gave the
installer.

### 5. Connect a device and add rules

1. Join the new Wi-Fi network. The **Wi-Fi Access Point** page has a QR code
   for phones.
2. Under **Routing Rules**, choose the **Default Behaviour** (direct, or a
   proxy), then add rules for the sites that should go the other way. If you
   don't know a service's hostnames, use it from a device for a minute, then
   look at **DNS Lookups**: every hostname has "New rule" / "Add to rule"
   links.
3. Use the rule tester on the Routing Rules page to check where a hostname
   will go. Changes reach connected devices within about a minute.

The [guide (PDF)](docs/Wi-Fi-Proxy-Hotspot-Guide.pdf) covers every page and
task in detail, and also has a one-page "how do I connect" section to hand to
the people using the hotspot.

## Updating

Back up first: **Backup & Restore → Export configuration**. Then choose one of
these:

- **Re-run the installer** after `git pull`. It reinstalls everything and
  **resets the configuration** to what you enter at its prompts. Import your
  export afterwards to get your profiles and rules back.
- **`deploy.sh`** from a development machine pushes only the changed code
  files over SSH and restarts only the affected services. It needs SSH key
  access and passwordless `sudo` on the box. Put an SSH config with a host
  alias in `keys/ssh_config` (gitignored), then run
  `./deploy.sh --dry-run --host <alias>` to see what would change.

## Uninstall

```bash
cd wifi-proxy-hotspot/package
sudo ./uninstall.sh
```

This removes the hotspot connection, firewall rules, services, helpers and
sudoers rules. The wired interface keeps its static IP, and the installed
apt packages stay; the script lists what to revert by hand if you want to.

## Security notes

- The admin panel listens only on the wired interface's address, over HTTPS
  (self-signed certificate), and requires a Linux login. **Devices on the
  hotspot can still connect to that address**, as they can to SSH on the
  box, because the box has no inbound filter on the Wi-Fi side. Both still
  need a Linux login, so use strong passwords, and don't share the hotspot
  with people you don't trust with that login prompt.
- The panel runs as an unprivileged service account. The few root actions it
  needs are allowed by exact command in one sudoers file, which the guide
  lists in full.
- Proxy credentials, the SMTP password and the Wi-Fi passphrase are stored
  **only on the box**, in root/service-owned files that other users can't
  read. A **configuration export contains proxy and SMTP passwords in plain
  text**, so treat that file like a password.
- A proxy hides your address from the sites you visit, **not from the proxy
  operator**, who can see where your traffic goes. Only use proxies you trust.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Hotspot doesn't appear, or no 5 GHz channels are offered | Wi-Fi country not set (step 2), or the radio is rfkill-blocked. |
| Admin panel unreachable | You're on the hotspot instead of the wired network, or the wired IP changed. Check `ip -4 addr` on the box. |
| A site still goes direct (or still via proxy) | It uses other hostnames too. Check **DNS Lookups** and the rule tester. Changes take up to a minute, or reconnect the device. |
| Proxied sites feel slow | Each new connection pays the round trip to the proxy. A far-away proxy adds about half a second per round trip. Use **Check** on Proxy Profiles, keep Proxied Lookups on for streaming, and on a Pi check the power supply (`vcgencmd get_throttled` should be `0x0`). |
| Something is red on Overview | Each tile names the failing check. The guide's troubleshooting section covers each one. |

## Development

This is a deployment bundle (a Flask admin app, root-owned helper scripts and
shell installers), not a pip-installable package. The box gets its
dependencies from `apt`. `pyproject.toml` holds the version (shown on the Help
page) and the dependency versions for local development.

```
package/       everything that gets installed on the box (install.sh is the entry point)
  templates/   the admin panel's Jinja templates (one file per page)
docs/          the admin & user guide (PDF) and the script that builds it
tests/         the test suite (runs anywhere: every OS call is faked)
deploy.sh      push code changes to an installed box over SSH
```

Because PAM, `nmcli`, `iptables`, `ipset` and a real Wi-Fi radio don't exist
on a development machine, the tests fake every OS-boundary call and check the
logic around it: the rendered admin page (tag balance, inline scripts passing
`node --check`, no secrets in the page), the exact firewall rules and their
order, DNS tagging and capture, the health-check alert logic, the proxy
checks against fake local proxies, and drift guards between the installer,
`deploy.sh`, the guide and the Help page.

```bash
pip install pytest flask dnspython qrcode
python -m pytest -q tests
```

The tests prove logic, templates and inline JavaScript, not hardware
behaviour. CI runs them on every push with Python 3.11 and 3.13.

To rebuild the guide after changing it (needs `pip install reportlab`):

```bash
python docs/build_guide.py      # writes docs/ and package/ copies of the PDF
```

## Contributing

Issues and pull requests are welcome, but **this project is not regularly
maintained**, so replies may be slow or may not come at all. You're
encouraged to fork it and adapt it to your needs; that's what the MIT license
is for. If you send a change, please include a test and keep `python -m
pytest -q tests` passing.

## Credits

Created by **Gerry Dassi**.

It stands on the shoulders of these open-source projects:

| Project | Used for | License |
|---|---|---|
| [redsocks](https://github.com/darkk/redsocks) | Transparent TCP-to-proxy redirector | Apache-2.0 |
| [NetworkManager](https://networkmanager.dev/) / dnsmasq | Wi-Fi access point, DHCP, NAT, DNS cache | GPL-2.0+ |
| [iptables](https://www.netfilter.org/) / [ipset](https://ipset.netfilter.org/) | Firewall routing and per-domain matching | GPL-2.0 |
| [Flask](https://flask.palletsprojects.com/) | Admin panel | BSD-3-Clause |
| [Gunicorn](https://gunicorn.org/) | Admin panel web server | MIT |
| [dnspython](https://www.dnspython.org/) | DNS router | ISC |
| [python-qrcode](https://github.com/lincolnloop/python-qrcode) | Wi-Fi join QR code | BSD-3-Clause |
| [python-pam](https://github.com/FirefighterBlu3/python-pam) | Linux-account login | MIT |
| [ReportLab](https://www.reportlab.com/opensource/) | Building the PDF guide (development only) | BSD |

The two patches in `package/redsocks-patches/` modify redsocks and are
distributed under redsocks' Apache-2.0 license.

## License

[MIT](LICENSE) © 2026 Gerry Dassi. The admin panel's Help page shows the same
license text, the credits and this disclaimer.

## Disclaimer

This software is provided **"as is"**, without warranty of any kind, express
or implied (see [LICENSE](LICENSE)). It is a personal project shared in the
hope that it is useful. It is **not regularly maintained**, and there is no
guaranteed support, fixes or updates.

It changes your system's network configuration, firewall and sudoers. Install
it on a dedicated box, not on a machine you depend on for something else.

You are responsible for how you use it. Comply with the laws where you live,
the policies of the network the box is connected to, and the terms of service
of your proxy provider and of any service you reach through it. Some
streaming services, for example, forbid using proxies to change your apparent
location.
