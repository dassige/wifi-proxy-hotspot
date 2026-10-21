import datetime
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, 'pdfgen'))
from renderer import DocBuilder

OUT = os.path.join(_HERE, 'Wi-Fi-Proxy-Hotspot-Guide.pdf')

# The version shown in the footer is the project's own, from pyproject.toml.
with open(os.path.join(os.path.dirname(_HERE), 'pyproject.toml'), encoding='utf-8') as _f:
    VERSION = re.search(r'^version\s*=\s*"([^"]+)"', _f.read(), re.M).group(1)
_TODAY = datetime.date.today()
GEN_DATE = f'{_TODAY.day} {_TODAY.strftime("%B %Y")}'

b = DocBuilder(
    output_path = OUT,
    title       = 'Wi-Fi Proxy Hotspot — Administration & User Guide',
    subtitle    = ('Reference build: Raspberry Pi 3B+ (Debian 13 Trixie) — runs on other '
                   'Debian-based Linux boxes with NetworkManager'),
    version     = f'v{VERSION}',
    org         = 'Gerry Dassi — MIT License',
    gen_date    = GEN_DATE,
    author      = 'Gerry Dassi',
)

b.title_bar()

# ── 1. Overview ──────────────────────────────────────────────────────────────
b.section('1', 'Overview')
b.body(
    'This guide covers a Wi-Fi hotspot that sits between any device that joins its wireless '
    'network and the internet. Every device that connects to the hotspot has its outbound TCP '
    'traffic sent, by a <b>configurable global default</b>, either direct or through one of '
    'several saved upstream proxy profiles (so those connections appear to originate from that '
    'proxy rather than from this network) — while an administrator-chosen internal IP range is '
    'always reached directly regardless of that default, and an ordered list of <b>routing '
    'rules</b> lets specific domains be sent direct or through any saved proxy, independently of '
    'the default and of each other.'
)
b.body(
    'A small locally-hosted web panel, protected by the box\u2019s own Linux login (no separate '
    'account to manage), lets an administrator maintain a saved list of upstream proxy profiles '
    '\u2014 each with its own name, description, type, address and credentials \u2014 alongside '
    'changing the Wi-Fi network devices connect to, the global default, the internal bypass '
    'range, and the routing rules. Every saved profile is reachable at all times; there is no '
    'single "active" proxy to switch \u2014 the default and each rule simply name which profile (or '
    '"direct") they want. All of this happens with no command line required once installed, and '
    'the panel also lists which devices are currently connected.'
)
b.table(
    headers = ['Property', 'Reference build value'],
    rows = [
        ['Hardware', 'Raspberry Pi 3B+ (other Debian-based boxes should work \u2014 see Section 3)'],
        ['OS', 'Debian 13 (Trixie), NetworkManager + netplan'],
        ['Wired interface (management / internet)', 'eth0 \u2014 static 192.168.1.10/24, gateway 192.168.1.1'],
        ['Internal network (bypass range)', '192.168.1.0/24'],
        ['Wireless interface (hotspot)', 'wlan0 \u2014 NetworkManager AP connection "Gateway-AP"'],
        ['Hotspot subnet', '192.168.4.0/24 (gateway 192.168.4.1)'],
        ['Admin panel', 'https://192.168.1.10:8443/'],
    ],
    col_ratios = [0.45, 0.55],
)
b.body(
    'The addresses above are examples used consistently throughout this guide; substitute your '
    'own internal network\u2019s addressing. A typical use is a hotspot in one country whose devices '
    'should reach selected services through a proxy in another, while everything else goes '
    'direct.'
)
b.note(
    'This guide describes both an automated installer (package/install.sh in the project '
    'repository) and the full manual procedure it automates. Use the installer for a normal build; '
    'read the manual section if you want to understand or adapt what it does.'
)

# ── 2. Architecture ─────────────────────────────────────────────────────────
b.section('2', 'Architecture')
b.body(
    'Traffic flow for a device joining the hotspot:'
)
b.bullets([
    'Device associates with the Wi-Fi access point (NetworkManager "shared" connection on the wireless interface) and receives a DHCP lease on the hotspot subnet.',
    'NetworkManager itself provides DHCP, NAT (masquerade) and IP forwarding for that connection \u2014 no separate hostapd/dnsmasq daemons are used.',
    'An iptables NAT PREROUTING rule intercepts the device\u2019s outbound TCP and, for each packet, checks three things in order: is the destination in the internal bypass CIDR (always direct, wins over everything)? does it match a routing rule\u2019s ipset (that rule\u2019s action \u2014 direct, or a named proxy profile \u2014 wins)? if neither, the configurable <b>global default</b> applies (direct, or a named proxy profile).',
    'redsocks runs as a single instance with one `redsocks{}` block per saved proxy profile, each listening on its own permanent local port \u2014 so every saved profile is reachable simultaneously, and a rule or the default naming a given profile is simply an iptables REDIRECT to that profile\u2019s port. When the outcome is "direct", the packet is simply returned to normal routing/NAT instead, exactly like internal-network traffic.',
    'Non-TCP traffic (e.g. DNS) is not intercepted by redsocks and follows normal routing/NAT \u2014 see the Notes section for the privacy implication of this.',
])
b.note(
    'A single Wi-Fi radio cannot normally act as a hotspot and a client of another network at the '
    'same time. If the wireless interface was previously connected to an existing Wi-Fi network, '
    'building this hotspot on it will end that connection permanently (or use a second, dedicated '
    'Wi-Fi adapter for the hotspot if that existing connection must be kept).'
)

b.body('<b>2.1 \u2014 How routing rules work</b>')
b.body(
    'redsocks and iptables only see IP addresses and ports \u2014 they have no visibility into the '
    'hostname a device is actually trying to reach. To route by domain, a small daemon '
    '(<b>dns_router.py</b>, running as its own unprivileged service account, granted only the '
    'CAP_NET_ADMIN capability via systemd) sits between the hotspot\u2019s own dnsmasq and the real '
    'internet:'
)
b.bullets([
    'Every DNS query from a hotspot device reaches dnsmasq as normal, which forwards it to the daemon as its first-choice upstream (dnsmasq runs in strict order; the box’s own resolvers are only a fallback if the daemon doesn’t answer, so DNS keeps working, just without tagging, if the daemon is ever down).',
    'dnsmasq answers repeat lookups from its own cache without asking the daemon, so two things keep rule changes from waiting on that cache: every firewall rebuild (which every rule change triggers) clears dnsmasq’s cache, and dnsmasq hands clients a TTL of at most 60 seconds (max-ttl=60), so devices ask again within a minute. A new, edited, enabled or disabled rule therefore reaches already-connected devices within about a minute for new connections; a connection that is already open (a video mid-playback) keeps its route until it reconnects.',
    'The daemon checks the queried hostname against the admin\u2019s ordered list of pattern rules (exact match, wildcard, or regular expression) \u2014 the first match wins.',
    'The daemon forwards the query to the box\u2019s real upstream DNS servers and always returns the genuine answer \u2014 it never blocks, delays meaningfully, or rewrites a DNS response.',
    'If a rule matched, the resolved IP address(es) are tagged into that rule\u2019s own `ipset` (with a 24-hour timeout, so stale entries self-expire). An IP the daemon hasn\u2019t tagged in the last hour is tagged <i>before</i> the answer is returned (one `ipset restore` call, ~4ms), so the device\u2019s very first connection to it is already routed correctly; repeat lookups add no delay. Changing a rule\u2019s pattern or mode gives it a fresh, empty ipset, so addresses its old pattern matched don\u2019t stay routed by it.',
    'Proxied Lookups (on by default, Routing Rules page): a hostname matched by a rule that routes through a proxy is looked up <i>through that proxy</i>, over DNS-over-HTTPS to Google (dns.google), so CDNs answer with servers near the proxy instead of near the hotspot. Measured on the reference build, with the hotspot and the proxy on different continents, streaming a live video channel: a 10-second segment took a median 7.3 s from the CDN server near the hotspot (worst 10.2 s, longer than it plays) vs 3.7 s from the one near the proxy that it now gets. EDNS Client Subnet would not have helped: the CDN in question (Akamai) ignores it. The daemon keeps two tunnels open through each such proxy and pings them to keep them warm, so these lookups cost one round trip (~0.3 s). If no tunnel is ready it uses ordinary DNS at once, never waiting. The default route, and everything not matched by a proxied rule, keep ordinary DNS.',
    'Separately, for the admin panel\u2019s DNS Lookups page, the daemon also passively watches the DNS queries devices send on the hotspot interface (a kernel packet filter lets through only UDP to port 53, so ordinary traffic never reaches it; this needs the CAP_NET_RAW capability as well). That is the only place a lookup can be tied to the device that made it: every query reaching the daemon itself comes from dnsmasq, and names dnsmasq answers from cache never reach it at all. The record is in memory only, snapshotted to /run/rasp-proxy-dns/lookups.json (RAM, readable only by the service group). If capture ever fails, only that page is affected, never DNS routing.',
    'The firewall\u2019s REDSOCKS chain has one rule per pattern rule, in the same order, matching traffic against that rule\u2019s ipset and sending it direct or into the named profile\u2019s redsocks port accordingly \u2014 exactly like the internal bypass CIDR, just IP-set-based instead of a static range. After all pattern rules, one final rule applies the configurable global default to anything left unmatched. An action naming a profile that has since been deleted is treated as direct (fail-safe) rather than erroring the whole rebuild \u2014 though the panel refuses to delete a profile that is still referenced anywhere, so this should only happen from manual JSON edits.',
])
b.note(
    'This only catches domains actually resolved through the hotspot\u2019s own DNS server. The Leak '
    'Guards (Routing Rules page, all on by default) close the common gaps: plain DNS sent to an '
    'outside server is redirected to the hotspot, DNS-over-TLS (port 853) is blocked, Firefox\u2019s '
    'DoH is switched off via its canary domain, iCloud Private Relay is turned off for the network, '
    'and forwarded IPv6 is blocked. What remains is an app with its own hard-coded DNS-over-HTTPS '
    '(indistinguishable from ordinary HTTPS on port 443). Such an app still gets whichever default '
    'is configured, so "direct by default, proxy only for specific domains" is not a hard guarantee '
    'for every possible packet.'
)
b.note(
    'Because matching is by resolved IP rather than by inspecting each connection\u2019s real '
    'destination, a large CDN-hosted domain that shares IP addresses with unrelated sites can '
    'occasionally over-match (an unrelated site on the same IP gets the same treatment) or '
    'under-match (a domain\u2019s IP changes before the next lookup refreshes the ipset). Keep this '
    'in mind for domains fronted by big shared CDNs; it is rarely noticeable for single-tenant '
    'services.'
)
b.warning(
    'The DNS router is a new always-running service directly in the hotspot\u2019s DNS resolution '
    'path. It is designed to fail open (any internal error just forwards the query unmatched rather '
    'than blocking it) and restarts automatically on crash, but if it stops entirely, hotspot '
    'devices lose DNS resolution, not just pattern matching. Its own health is worth including in '
    'routine checks (see Section 5).'
)

# ── 3. Prerequisites ─────────────────────────────────────────────────────────
b.section('3', 'Prerequisites')
b.body('<b>3.1 \u2014 Hardware and operating system</b>')
b.body(
    'The project was built and tested on a <b>Raspberry Pi 3B+ running Debian 13 (Trixie) / '
    'Raspberry Pi OS</b>, and that is the only hardware it has actually been tested on. Nothing in '
    'it is Pi-specific, though, apart from the optional under-voltage and temperature readings on '
    'the Overview page (which simply show as unavailable elsewhere), so any Debian 12+ based Linux '
    'box should work \u2014 for example a Raspberry Pi 4 or 5, a Raspberry Pi Zero 2 W with a USB '
    'Ethernet adapter, or a small x86 mini PC \u2014 provided it has:'
)
b.bullets([
    'NetworkManager managing its network interfaces (the `nmcli` command must exist). Older Raspberry Pi OS Legacy/Bullseye images use `dhcpcd`/`hostapd`/`dnsmasq` instead \u2014 see the note in Section 8 for the manual equivalent on that stack.',
    'A wired Ethernet interface for the upstream internet connection and for management (the admin panel is only served there).',
    'A Wi-Fi adapter that supports access-point mode: run `iw list` and check that "Supported interface modes" includes "AP".',
    'About 1 GB of RAM is plenty; the whole stack is light enough for a Pi 3B+.',
])
b.code(
    'iw list | grep -A 10 "Supported interface modes"   # must include: * AP'
)

b.body('<b>3.2 \u2014 Set the Wi-Fi country (regulatory domain) first</b>')
b.body(
    'The Wi-Fi radio\u2019s usable channels depend on the country it is set to, and on Raspberry Pi OS '
    'the radio stays blocked (rfkill) until a country has been set at all \u2014 the hotspot then '
    'simply fails to start. Set it before installing, replacing XX with your two-letter country '
    'code (e.g. GB, US, DE):'
)
b.code(
    '# Raspberry Pi OS (or interactively: sudo raspi-config -> Localisation Options -> WLAN Country)\n'
    'sudo raspi-config nonint do_wifi_country XX\n\n'
    '# Other distributions: set it now ...\n'
    'sudo iw reg set XX\n'
    '# ... and persist it the distribution\u2019s way, e.g. by adding\n'
    '#     cfg80211.ieee80211_regdom=XX\n'
    '# to the kernel command line\n\n'
    '# Either way, check the radio isn\u2019t blocked, and unblock it if it is:\n'
    'rfkill list\n'
    'sudo rfkill unblock wifi\n'
    'iw reg get   # confirm the country took effect'
)
b.note(
    'The admin panel\u2019s band and channel picker only offers channels the radio reports as usable '
    'for an access point under the current country. If no 5 GHz choices appear, the Wi-Fi country '
    'is most likely not set.'
)

b.body('<b>3.3 \u2014 What you need before installing</b>')
b.bullets([
    'A wired interface already reachable on your internal network (DHCP is fine \u2014 it becomes static during setup).',
    'A wireless interface free to dedicate to the hotspot.',
    'Root access on the box, and `git` to fetch the code.',
    'The upstream proxy\u2019s type (HTTP or SOCKS5), address, port, and credentials if it requires authentication.',
    'The internal IP range (CIDR) that hotspot devices should be able to reach directly, without going through the proxy.',
    'Any domains you already know should always (or never) go through the proxy, if using routing rules from the start — these can also be added later via the panel.',
])

# ── 4. Installation (Admin) ──────────────────────────────────────────────────
b.section('4', 'Installation (Admin)')
b.body('<b>4.1 \u2014 Quick install (recommended)</b>')
b.body(
    'Clone the repository onto the target machine and run the installer as root from its '
    '<b>package/</b> folder. It interactively asks for every value in the Prerequisites section '
    'above and applies all of Section 4.2 automatically.'
)
b.code(
    'sudo apt-get install -y git\n'
    'git clone https://github.com/dassige/wifi-proxy-hotspot.git\n'
    'cd wifi-proxy-hotspot/package && sudo ./install.sh'
)
b.note(
    'Run the installer from a full clone rather than copying the package/ folder on its own: it '
    'reads the version number from pyproject.toml, one directory above package/, and stops if it '
    'is missing. Besides the packages listed in Step 2 it makes sure dnsmasq-base (the DNS/DHCP '
    'server NetworkManager uses for the hotspot) and openssl (for the panel’s certificate) are '
    'installed, since minimal images don’t always include them.'
)
b.warning(
    'If you are connected to the box over SSH via the same wired interface being given a new '
    'static IP, your session will drop partway through the install \u2014 this is expected. Wait a '
    'few seconds and reconnect on the new address.'
)
b.body(
    'At the end, the installer prints the hotspot SSID/passphrase and the admin panel URL. To '
    'remove everything it created, run <b>sudo ./uninstall.sh</b> from the same folder.'
)

b.spacer(2)
b.body('<b>4.2 \u2014 Manual install, step by step</b>')
b.body('This is exactly what install.sh automates, for reference or manual adaptation.')

b.step(
    'Step 1 \u2014 Static IP on the wired interface',
    body='Find the active NetworkManager connection on the interface and set it to a fixed address:',
    code=(
        'CONN=$(nmcli -t -f GENERAL.CONNECTION device show eth0 | cut -d: -f2)\n'
        'sudo nmcli connection modify "$CONN" \\\n'
        '    ipv4.method manual ipv4.addresses 192.168.1.10/24 \\\n'
        '    ipv4.gateway 192.168.1.1 ipv4.dns "192.168.1.1 1.1.1.1"\n'
        'sudo nmcli connection up "$CONN"'
    ),
)
b.warning(
    'If the interface already has two NetworkManager profiles (e.g. an auto-created default '
    'alongside a netplan-managed one), only one can be active at a time and the wrong one winning '
    'is a common, silent failure mode. Confirm with `nmcli connection show` that the DEVICE column '
    'points the profile you just modified at the interface, and disable autoconnect on any other '
    'profile bound to the same interface: `nmcli connection modify <other-name> connection.autoconnect no`.'
)
b.step(
    'Step 2 \u2014 Install packages',
    code=(
        'echo iptables-persistent iptables-persistent/autosave_v4 boolean false | sudo debconf-set-selections\n'
        'echo iptables-persistent iptables-persistent/autosave_v6 boolean false | sudo debconf-set-selections\n'
        'sudo apt-get update\n'
        'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \\\n'
        '    redsocks iptables-persistent python3-flask python3-pam gunicorn iw \\\n'
        '    python3-dnspython ipset python3-qrcode dnsmasq-base openssl'
    ),
)
b.step(
    'Step 3 \u2014 Create the Wi-Fi access point',
    body=(
        'NetworkManager\u2019s own "shared" method provides DHCP, NAT and IP forwarding for this '
        'connection \u2014 no hostapd/dnsmasq needed. The dnsmasq-shared.d file points the hotspot\u2019s '
        'DNS at the pattern-router daemon (deployed in Step 7, started in Step 7b) and caps the TTL '
        'handed to clients at 60s so rule changes reach them quickly; it must exist before the first '
        'activation (NetworkManager only reads it when it starts the hotspot\u2019s dnsmasq):'
    ),
    code=(
        'sudo nmcli connection add type wifi ifname wlan0 con-name Gateway-AP \\\n'
        '    autoconnect yes ssid "<your-ssid>"\n'
        'sudo nmcli connection modify Gateway-AP 802-11-wireless.mode ap 802-11-wireless.band bg\n'
        'sudo nmcli connection modify Gateway-AP wifi-sec.key-mgmt wpa-psk\n'
        'sudo nmcli connection modify Gateway-AP wifi-sec.psk "<your-passphrase>"\n'
        'sudo nmcli connection modify Gateway-AP ipv4.method shared ipv4.addresses 192.168.4.1/24\n\n'
        'sudo mkdir -p /etc/NetworkManager/dnsmasq-shared.d\n'
        'sudo tee /etc/NetworkManager/dnsmasq-shared.d/pattern-routing.conf > /dev/null <<EOF\n'
        'server=127.0.0.1#15353\n'
        'max-ttl=60\n'
        'EOF\n\n'
        'sudo nmcli connection up Gateway-AP'
    ),
)
b.step(
    'Step 4 \u2014 Configure redsocks',
    body=(
        'Write /etc/redsocks.conf with one redsocks{} block per saved proxy profile, each on its '
        'own permanent local port starting at 20000 (this is what lets different rules use '
        'different proxies simultaneously) \u2014 the first profile, created here, always takes '
        '20000:'
    ),
    code=(
        'sudo tee /etc/redsocks.conf > /dev/null <<EOF\n'
        'base {\n'
        '    log_info = on;\n'
        '    daemon = on;\n'
        '    redirector = iptables;\n'
        '}\n'
        'redsocks {\n'
        '    local_ip = 0.0.0.0;\n'
        '    local_port = 20000;\n'
        '    ip = <proxy-ip>;\n'
        '    port = <proxy-port>;\n'
        '    type = http-connect;   # or socks5\n'
        '    login = "<proxy-username>";\n'
        '    password = "<proxy-password>";\n'
        '}\n'
        'EOF\n'
        'sudo chown root:redsocks /etc/redsocks.conf && sudo chmod 660 /etc/redsocks.conf\n'
        'sudo systemctl enable --now redsocks'
    ),
)
b.step(
    'Step 4b — redsocks performance patches (optional)',
    body=(
        'Stock redsocks waits for the proxy to reject a connection before sending its Basic-auth '
        'credentials, and never sets TCP_NODELAY on its sockets; both cost extra round trips on a '
        'long, high-latency link to a proxy abroad. package/redsocks-patches/ holds two small '
        'patches fixing that. The installer fetches the distribution’s own redsocks source with '
        '`apt-get source redsocks` (if no deb-src entry is configured it adds a temporary one for '
        'the running release, using the codename from /etc/os-release, and removes it afterwards), '
        'applies both patches to whatever source version apt fetched, builds it and replaces '
        '/usr/sbin/redsocks, keeping the stock binary as /usr/sbin/redsocks.orig-&lt;version&gt;. '
        'This step is best-effort: if anything fails the stock binary stays in place and the '
        'install carries on. To do it by hand:'
    ),
    code=(
        'sudo apt-get install -y build-essential dpkg-dev libevent-dev\n'
        'mkdir -p /tmp/redsocks-build && cd /tmp/redsocks-build\n'
        'apt-get source redsocks          # needs a deb-src entry for your release\n'
        'cd redsocks-*/\n'
        'patch -p1 < /path/to/package/redsocks-patches/0001-tcp-nodelay.patch\n'
        'patch -p1 < /path/to/package/redsocks-patches/0002-preemptive-basic-auth.patch\n'
        'make\n'
        'sudo cp /usr/sbin/redsocks /usr/sbin/redsocks.orig\n'
        'sudo install -m 755 -o root -g root redsocks /usr/sbin/redsocks\n'
        'sudo systemctl restart redsocks'
    ),
)
b.note(
    'A later redsocks package upgrade puts the stock binary back. Re-run the steps above (or '
    're-run the installer) to reapply the patches; everything works either way, only more slowly '
    'through a distant proxy without them.'
)
b.step(
    'Step 5 \u2014 Firewall: redirect hotspot traffic into redsocks',
    body=(
        'This is the baseline chain matching the one profile created so far \u2014 internal range '
        'excluded (always direct), everything else redirected to that profile\u2019s port 20000. Step '
        '7a rebuilds this properly from the actual JSON stores once they exist, using the same '
        'helper the admin panel uses for every later change \u2014 this manual version only needs to '
        'get redsocks working long enough to reach that point:'
    ),
    code=(
        'sudo iptables -t nat -N REDSOCKS\n'
        'sudo iptables -t nat -A REDSOCKS -d 192.168.1.0/24 -j RETURN\n'
        'sudo iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 20000\n'
        'sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp -j REDSOCKS\n'
        'sudo netfilter-persistent save'
    ),
)
b.warning(
    'A REDIRECT rule\u2019s --to-ports option requires an explicit port-capable protocol match '
    '(-p tcp) on that specific rule \u2014 it is not inherited from the chain it lives in. Omitting '
    'it fails with "Need TCP, UDP, SCTP or DCCP with port specification". This matters for every '
    'rule that targets REDIRECT: the catch-all above when the default names a proxy profile, and '
    'any pattern rule whose action names a profile. A rule targeting RETURN (default "direct", '
    'or a pattern rule '
    'set to "direct") needs no protocol match at all.'
)
b.step(
    'Step 6 \u2014 Dedicated, unprivileged service accounts',
    body='One for the admin panel, one for the DNS pattern-router daemon (Step 7b):',
    code=(
        'sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid redsocks proxyadmin-svc\n'
        'sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid redsocks rasp-proxy-dns'
    ),
)
b.step(
    'Step 7 \u2014 Deploy the admin web app and its root-owned helpers',
    body='From the package folder:',
    code=(
        'sudo mkdir -p /opt/rasp-proxy-admin\n'
        'sudo install -m 640 -o root -g redsocks app.py /opt/rasp-proxy-admin/app.py\n'
        'sudo install -m 640 -o root -g redsocks dns_router.py /opt/rasp-proxy-admin/dns_router.py\n'
        'sudo install -m 640 -o root -g redsocks pattern_match.py /opt/rasp-proxy-admin/pattern_match.py\n'
        'sudo install -m 640 -o root -g redsocks proxy_check.py /opt/rasp-proxy-admin/proxy_check.py\n'
        'sudo install -m 640 -o root -g redsocks proxy_doh.py /opt/rasp-proxy-admin/proxy_doh.py\n'
        'sudo install -m 640 -o root -g redsocks mailer.py /opt/rasp-proxy-admin/mailer.py\n'
        'sudo install -m 640 -o root -g redsocks help_texts.py /opt/rasp-proxy-admin/help_texts.py\n'
        'sudo cp -r templates /opt/rasp-proxy-admin/ && sudo chown -R root:redsocks /opt/rasp-proxy-admin/templates\n'
        'sudo find /opt/rasp-proxy-admin/templates -type d -exec chmod 750 {} +\n'
        'sudo find /opt/rasp-proxy-admin/templates -type f -exec chmod 640 {} +\n'
        'sudo chown root:redsocks /opt/rasp-proxy-admin && sudo chmod 750 /opt/rasp-proxy-admin\n'
        'sudo install -m 750 -o root -g root rasp-proxy-pamcheck.py /usr/local/sbin/rasp-proxy-pamcheck\n'
        'sudo install -m 750 -o root -g root rasp-proxy-rebuild-firewall.py /usr/local/sbin/rasp-proxy-rebuild-firewall\n'
        'sudo install -m 750 -o root -g root rasp-proxy-traffic-sync.py /usr/local/sbin/rasp-proxy-traffic-sync\n'
        'sudo install -m 750 -o root -g root rasp-proxy-health.py /usr/local/sbin/rasp-proxy-health\n'
        'sudo install -m 644 -o root -g root pam-service /etc/pam.d/rasp-proxy-admin\n'
        'sudo mkdir -p /etc/rasp-proxy-admin/tls\n'
        'sudo openssl req -x509 -nodes -newkey rsa:2048 \\\n'
        '    -keyout /etc/rasp-proxy-admin/tls/key.pem -out /etc/rasp-proxy-admin/tls/cert.pem \\\n'
        '    -days 3650 -subj "/CN=wifi-proxy-hotspot.local"\n'
        'sudo chown -R root:redsocks /etc/rasp-proxy-admin\n'
        'sudo chmod 750 /etc/rasp-proxy-admin /etc/rasp-proxy-admin/tls\n'
        'sudo chmod 640 /etc/rasp-proxy-admin/tls/*.pem'
    ),
)
b.step(
    'Step 7a \u2014 Create the mutable state directory and stores',
    body=(
        'Both the proxy-profile list and the pattern-rule list live under /var/lib, not /etc, and '
        'must be owned by the service account itself \u2014 /var/lib is not group-writable, so the '
        'unprivileged app could never create this directory on its own the first time it tries to '
        'save anything:'
    ),
    code=(
        'sudo mkdir -p /var/lib/rasp-proxy-admin\n'
        'sudo chown proxyadmin-svc:redsocks /var/lib/rasp-proxy-admin\n'
        'sudo chmod 750 /var/lib/rasp-proxy-admin\n\n'
        '# bypass_cidr lives in this file (not derived from live iptables output)\n'
        '# specifically so the firewall can be rebuilt from scratch at boot \u2014 see\n'
        '# Step 11 for why that matters:\n'
        "sudo tee /var/lib/rasp-proxy-admin/pattern_rules.json > /dev/null <<EOF\n"
        '{\n'
        '  "bypass_cidr": "192.168.1.0/24",\n'
        '  "default_action": "default",\n'
        '  "rules": []\n'
        '}\n'
        'EOF\n'
        'sudo chown proxyadmin-svc:redsocks /var/lib/rasp-proxy-admin/pattern_rules.json\n'
        'sudo chmod 640 /var/lib/rasp-proxy-admin/pattern_rules.json\n\n'
        '# Re-derive the chain from these stores using the same helper the panel\n'
        '# uses for every later change, rather than trusting Step 5\u2019s hand-built\n'
        '# version to stay in sync with it:\n'
        'sudo /usr/local/sbin/rasp-proxy-rebuild-firewall wlan0'
    ),
)
b.warning(
    'This step is not optional. The panel auto-creates a "default" proxy profile (assigned local '
    'port 20000, matching Step 4) from whatever is in /etc/redsocks.conf the first time it loads '
    '\u2014 but that first write still needs somewhere to land. Skip this step and the very first '
    'page load will fail outright, since the unprivileged app cannot create a new directory under '
    '/var/lib itself. The default_action value above assumes that auto-created profile is still '
    'named "default"; if you already know you\u2019ll rename or replace it, adjust accordingly once '
    'the panel is up.'
)
b.step(
    'Step 7b \u2014 DNS pattern-router service',
    body=(
        'Runs as the unprivileged rasp-proxy-dns account, with only CAP_NET_ADMIN granted via '
        'systemd \u2014 enough to call `ipset` directly, nothing else:'
    ),
    code=(
        'sudo tee /etc/systemd/system/rasp-proxy-dns-router.service > /dev/null <<EOF\n'
        '[Unit]\n'
        'Description=Wi-Fi Proxy Hotspot DNS pattern router\n'
        'After=network-online.target\n'
        '[Service]\n'
        'Type=simple\n'
        'User=rasp-proxy-dns\n'
        'Group=redsocks\n'
        'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n'
        'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n'
        'NoNewPrivileges=true\n'
        'Environment=RASP_PROXY_AP_IFACE=wlan0\n'
        'RuntimeDirectory=rasp-proxy-dns\n'
        'RuntimeDirectoryMode=0750\n'
        'WorkingDirectory=/opt/rasp-proxy-admin\n'
        'ExecStart=/usr/bin/python3 /opt/rasp-proxy-admin/dns_router.py\n'
        'Restart=always\n'
        'RestartSec=2\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
        'EOF\n'
        'sudo systemctl daemon-reload && sudo systemctl enable --now rasp-proxy-dns-router'
    ),
)
b.step(
    'Step 8 \u2014 Sudoers: the exact, minimal root actions the web app needs',
    body='Validate with `visudo -c -f` before installing to /etc/sudoers.d/ \u2014 a syntax error here can lock out sudo entirely:',
    code=(
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/local/sbin/rasp-proxy-pamcheck admin\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/systemctl restart redsocks\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli connection modify Gateway-AP *\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli connection up Gateway-AP\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli connection down Gateway-AP\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /bin/cat /var/lib/NetworkManager/dnsmasq-wlan0.leases\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/local/sbin/rasp-proxy-rebuild-firewall *\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/sbin/iptables -t nat -L REDSOCKS -n\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/systemd-run --on-active=3 /usr/sbin/reboot\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/local/sbin/rasp-proxy-traffic-sync *\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/sbin/iptables -t mangle -L WPXACCT_UP -n -v -x\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/sbin/iptables -t mangle -L WPXACCT_DOWN -n -v -x\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block rasp-proxy-health.service\n'
        'proxyadmin-svc ALL=(root) NOPASSWD: /usr/bin/nmcli -s -g 802-11-wireless-security.psk connection show Gateway-AP'
    ),
)
b.step(
    'Step 9 \u2014 systemd service for the admin panel',
    code=(
        'sudo tee /etc/systemd/system/rasp-proxy-admin.service > /dev/null <<EOF\n'
        '[Unit]\n'
        'Description=Wi-Fi Proxy Hotspot admin web panel\n'
        'After=network-online.target\n'
        '[Service]\n'
        'Type=simple\n'
        'User=proxyadmin-svc\n'
        'Group=redsocks\n'
        'WorkingDirectory=/opt/rasp-proxy-admin\n'
        'Environment=RASP_PROXY_ADMIN_USERS=admin\n'
        'Environment=RASP_PROXY_AP_CONN=Gateway-AP\n'
        'Environment=RASP_PROXY_AP_IFACE=wlan0\n'
        f'Environment=RASP_PROXY_VERSION={VERSION}\n'
        'Environment="RASP_PROXY_VERSION_DATE=<install date, YYYY/MM/DD HH:MM>"\n'
        'ExecStart=/usr/bin/gunicorn --bind 192.168.1.10:8443 \\\n'
        '  --certfile=/etc/rasp-proxy-admin/tls/cert.pem --keyfile=/etc/rasp-proxy-admin/tls/key.pem \\\n'
        '  --workers 2 app:app\n'
        'Restart=on-failure\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
        'EOF\n'
        'sudo systemctl daemon-reload && sudo systemctl enable --now rasp-proxy-admin'
    ),
)
b.note(
    'Every service and connection above is enabled/autoconnect by default, so the whole stack — '
    'static IP, hotspot, redsocks, and the admin panel — comes back automatically after a reboot '
    'with no further action, confirmed by an actual reboot on the reference build. The firewall '
    'chain itself needs the dedicated boot service in Step 11 below to survive a reboot correctly '
    '— see the warning there for why.'
)
b.step(
    'Step 11 — Boot-time firewall rebuild (do not skip this)',
    body=(
        '`netfilter-persistent` saves iptables rules across reboots, but never `ipset` contents. '
        'Since the REDSOCKS chain’s pattern-rule entries reference ipsets by name, a saved rule '
        'pointing at an ipset that no longer exists after reboot makes the restore of the *entire* '
        'saved ruleset fail — `iptables-restore` applies its input as one atomic transaction. The '
        'practical effect discovered on the reference build: after a reboot, the REDSOCKS chain did '
        'not exist at all, and hotspot traffic went out completely unfiltered — no proxy, no '
        'pattern rules, silently. This service rebuilds the whole chain and its ipsets from scratch, '
        'from the same JSON state the admin panel uses, every time the box starts:'
    ),
    code=(
        'sudo tee /etc/systemd/system/rasp-proxy-firewall-init.service > /dev/null <<EOF\n'
        '[Unit]\n'
        'Description=Wi-Fi Proxy Hotspot firewall init (rebuilds REDSOCKS chain + ipsets on boot)\n'
        'After=network-online.target redsocks.service\n'
        'Wants=network-online.target\n'
        'Requires=redsocks.service\n'
        '[Service]\n'
        'Type=oneshot\n'
        'ExecStart=/usr/local/sbin/rasp-proxy-rebuild-firewall wlan0\n'
        'RemainAfterExit=yes\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
        'EOF\n'
        'sudo systemctl daemon-reload && sudo systemctl enable --now rasp-proxy-firewall-init'
    ),
)
b.warning(
    'If this service is missing (e.g. on a box built before it existed), the REDSOCKS chain will '
    'silently fail to come back after every reboot, and hotspot traffic will go out completely '
    'un-proxied and un-filtered with no error shown anywhere — check for it explicitly '
    '(`systemctl is-enabled rasp-proxy-firewall-init`) if migrating an older build.'
)
b.step(
    'Step 12 — Health check timer (Overview page + email alerts)',
    body=(
        'A root oneshot, run every 2 minutes by a timer, that checks the services, hotspot, firewall '
        'chains, DNS, every proxy and the box itself, and writes the results for the panel’s '
        'Overview page. It also sends the email alerts configured on the System page. It only ever '
        'reports; it never changes routing. Root is needed to read the firewall chains and the '
        'kernel log. Use the box’s real panel address in RASP_PROXY_PANEL_URL (it goes into '
        'alert emails):'
    ),
    code=(
        'sudo tee /etc/systemd/system/rasp-proxy-health.service > /dev/null <<EOF\n'
        '[Unit]\n'
        'Description=Wi-Fi Proxy Hotspot health check (Overview page + email alerts)\n'
        'After=network-online.target\n'
        '[Service]\n'
        'Type=oneshot\n'
        'Environment=RASP_PROXY_AP_IFACE=wlan0\n'
        'Environment=RASP_PROXY_AP_CONN=Gateway-AP\n'
        'Environment=RASP_PROXY_PANEL_URL=https://192.168.1.10:8443/\n'
        'ExecStart=/usr/local/sbin/rasp-proxy-health\n'
        'TimeoutStartSec=120\n'
        'Nice=10\n'
        'EOF\n'
        'sudo tee /etc/systemd/system/rasp-proxy-health.timer > /dev/null <<EOF\n'
        '[Unit]\n'
        'Description=Run the Wi-Fi Proxy Hotspot health check every 2 minutes\n'
        '[Timer]\n'
        'OnBootSec=90s\n'
        'OnUnitActiveSec=2min\n'
        'AccuracySec=15s\n'
        '[Install]\n'
        'WantedBy=timers.target\n'
        'EOF\n'
        'sudo systemctl daemon-reload && sudo systemctl enable --now rasp-proxy-health.timer'
    ),
)

# ── 5. Admin — day-to-day operation ─────────────────────────────────────────
b.section('5', 'Admin \u2014 Day-to-Day Operation')
b.body(
    'Once installed, routine changes go through the web panel rather than the command line: open '
    '<b>https://&lt;wired-ip&gt;:8443/</b> and log in with a Linux account listed in '
    'RASP_PROXY_ADMIN_USERS on the box. The browser will warn about the self-signed certificate; '
    'that is expected \u2014 accept it. The panel is a left-hand menu (Overview, Proxy Profiles, Wi-Fi Access '
    'Point, Internal Network, Routing Rules, Devices, DNS Lookups, Backup & Restore, System, Help) with one '
    'page shown at a time, rather than one long scrolling form \u2014 the browser remembers which page '
    'you were on across actions, and following an Edit link opens straight to the right page. '
    'The panel also works from a phone: on a narrow screen the menu becomes a row of tabs across '
    'the top that scrolls sideways, and each row of the wider tables (Proxy Profiles, Routing '
    'Rules, Devices) is shown as its own labelled block instead of a table row. The panel is only '
    'reachable on the wired side, so the phone must be on that network, not on the hotspot.'
)
b.table(
    headers = ['Task', 'Where'],
    rows = [
        ['See whether everything is working, at a glance', '"Overview" page (the first page; a coloured dot next to it in the menu shows the overall state from anywhere) — tiles for the services, hotspot and DNS, firewall chains, every proxy (working or not, round-trip time, exit IP with a geolocation hint) and the box itself (under-voltage, temperature, disk, memory), from checks that run every 2 minutes. "Run checks now" runs them straight away. A proxy that nothing uses shows amber, not red, when down, and never alerts'],
        ['Get an email when something breaks, and when it recovers', '"System" → "Email Alerts" — SMTP server, port, security, username/password (Gmail needs an app password), recipients; "Send test email" tries the form’s values before saving. A problem must show on two checks in a row (~4 minutes) before it’s emailed; recovery is emailed too, once the check has stayed OK for “Recovered after OK for” minutes (default 10; failing again before that stays the same problem, so a flapping proxy sends one PROBLEM and one RECOVERED email, not dozens); “At most one email every” (default 30 minutes) sends the first alert after a quiet spell at once and groups anything after it into one email, with the Overview showing when held alerts go out (0 turns either limit off); one-off notices cover the box restarting (optional), under-voltage in the kernel log, and a proxy’s exit IP changing. Emails that can’t be sent are kept and retried every 2 minutes. Alerts never change routing'],
['Add a new proxy profile (name, description, type, address, port, credentials)', '"Proxy Profiles" \u2192 "Add Proxy Profile" (collapsed by default; click to expand) \u2014 gets its own permanent local port automatically, reachable immediately'],
        ['Edit an existing proxy profile', '"Proxy Profiles" table \u2192 Edit button \u2014 opens the same form pre-filled; leave Password blank to keep it unchanged; its port never changes, so anything already pointed at it keeps working'],
        ['Disable a proxy you only run now and then (e.g. a test proxy you start on demand)', '"Proxy Profiles" table → its "Enabled" toggle — a disabled profile isn’t health-checked (grey on the Overview page) and never alerts. If active pattern rules use it, you’re asked to confirm and those rules are switched off too, so no traffic keeps going through an unwatched proxy. It can’t be disabled while it’s the Default Behaviour (point the default elsewhere first). It stays saved, shows "(disabled)" in the Action lists, and its Check button still works. Re-enabling it doesn’t turn those rules back on: do that under Routing Rules. Saving the toggle doesn’t restart redsocks'],
        ['Remove a saved proxy profile', '"Proxy Profiles" table \u2192 Delete button (confirmation required) \u2014 refused with a message listing exactly what still uses it (the default and/or named pattern rules) if it\u2019s in use'],
        ['Change the hotspot SSID or passphrase', '"Wi-Fi Access Point" page \u2014 reactivates the hotspot (if currently enabled); connected devices briefly drop and must rejoin'],
        ['Move the hotspot to 5 GHz (or another channel)', '"Wi-Fi Access Point" → "Band & channel" → Apply (confirmation required) — offers only the channels this radio reports as usable for an access point under the current Wi-Fi country (read from `iw list`: channels marked disabled, no-IR or needing radar detection are hidden), out of 2.4 GHz automatic/1/6/11 and 5 GHz automatic (the radio picks)/36/40/44/48/149/153/157/161/165; if `iw` can’t be read the full list is shown. No 5 GHz choices usually means the Wi-Fi country isn’t set (Section 3.2). 5 GHz is faster and less crowded but shorter-range, and 2.4 GHz-only devices can’t see it. Every device drops for a few seconds; if the hotspot can’t start on the new setting it reverts by itself and says so'],
        ['Let someone join by scanning a code instead of typing the password', '"Wi-Fi Access Point" → "Show join QR code" — a standard Wi-Fi QR code phone cameras understand. It contains the password: hide it again before others can see the screen. Needs the python3-qrcode package (installed by install.sh)'],
        ['Switch the panel to dark mode', 'The "Theme" picker at the bottom of the left-hand menu — Auto (follows the device’s own setting; phones always use this), Light or Dark; remembered by the browser'],
        ['Restart the Wi-Fi access point without changing anything', '"Wi-Fi Access Point" \u2192 "Restart Wi-Fi" button (confirmation required, disabled while the hotspot itself is off) \u2014 useful if the hotspot seems stuck'],
        ['Turn the hotspot radio off entirely, or back on', '"Wi-Fi Access Point" \u2192 "Disable Hotspot"/"Enable Hotspot" button (confirmation required to disable) \u2014 disabling drops every device immediately and keeps it off even across a reboot, until re-enabled here'],
        ['Change which internal range bypasses the proxy', '"Internal Network" page \u2014 rewrites and persists the firewall rule'],
        ['Change the global default (direct, or a named proxy profile) for everything not otherwise matched', '"Routing Rules" page, "Default Behaviour" section at the top \u2014 rebuilds and persists the whole firewall chain'],
        ['Add a routing rule (route a domain direct or to any saved proxy)', '"Routing Rules" \u2192 "Add Routing Rule" (collapsed by default) \u2014 choose exact/wildcard/regexp and the action. Patterns match hostnames only: the panel refuses anything that can never match (a URL, a path such as *.discoveryplus.com/*, a port), flags any existing rule like that, and warns when a wildcard covers a whole shared CDN such as *.akamaized.net'],
        ['Cover a whole service with one rule (site + its video CDNs)', '"Routing Rules" → Add/Edit — the Patterns box takes one pattern per line, and the rule matches if any of them does: one switch, one firewall entry. "Start from a preset" fills in the built-in presets, two streaming services verified on the reference build (RaiPlay: *raiplay.it, *.netrw.it, *.msvdn.net, mediapolis.rai.it; TV8: *tv8.it, *skycdn-it.akamaized.net). Adding patterns to a rule keeps everything it has already routed; removing one, or changing the mode, starts it afresh'],
        ['Check what will happen to a hostname before (or instead of) trying it on a device', '"Routing Rules" → "Test a hostname" — type a hostname or paste a URL: shows the winning rule and the pattern that matched, later rules it hides, switched-off rules that would match, whether it goes through a proxy and whether its lookup goes through the proxy too'],
        ['See whether each rule is actually doing anything', '"Routing Rules" table → Activity column — recent lookups each rule matched (from DNS Lookups, cache hits included) with the last one, and connections its firewall entry handled since the rules last changed (refreshed every 2 minutes by the health check). "No activity yet" on a busy service usually means the patterns miss the hostnames it really uses'],
        ['Stop devices routing around the rules', '"Routing Rules" → "Leak Guards" (all on by default): <b>Force all DNS through the hotspot</b> (plain DNS to outside servers, e.g. a TV hard-wired to 8.8.8.8, is answered by the hotspot; DNS-over-TLS on port 853 is blocked, so Android’s Private DNS in Automatic mode falls back to plain DNS, but a phone with Private DNS pinned to a provider will report no connection until it’s set to Automatic or Off; Firefox is told not to use its own DoH); <b>Block iCloud Private Relay</b> (Apple’s standard network signal; devices say it’s off for this network); <b>Block IPv6 from hotspot devices</b> (everything here is IPv4-only). Each shows how many attempts it caught; the internal range is never affected. The Overview’s "Leak guards" tile alerts if an enabled guard is missing from the firewall'],
        ['Make proxied video fetch from servers near the proxy, not near the hotspot', '"Routing Rules" → "Proxied Lookups" toggle (on by default) — hostnames matched by a proxied rule are looked up through that proxy, so CDNs hand out servers near it; the lines under the toggle show each proxy’s ready tunnels and how many lookups went through it or fell back to ordinary DNS (also an Overview tile). Turning it off returns those lookups to ordinary DNS'],
        ['Reorder pattern rules (earlier rules win)', '"Routing Rules" table \u2192 Move Up / Move Down on each rule\u2019s action row'],
        ['Temporarily switch a pattern rule off without deleting it', '"Routing Rules" table \u2192 the toggle switch in that rule\u2019s Status column \u2014 a disabled rule is skipped entirely, shown greyed out, and its settings are kept for later'],
        ['Edit or remove a pattern rule', '"Routing Rules" table \u2192 Edit or Delete (confirmation required) on that rule\u2019s action row'],
        ['See every device that has ever joined, not just those currently online', '"Devices" page \u2014 hostname, IP, MAC, Online/Offline/Blocked status, connection duration'],
        ['Give a device a recognisable name', '"Devices" table → "name it" / "rename" under the device — the nickname is used everywhere the device appears, including DNS Lookups'],
        ['Make one device always go direct, or always through a particular proxy', '"Devices" table → Routing — Follow the rules (default), Always direct, or Always through a proxy (e.g. a TV box that should always appear to be in the proxy’s country). It overrides every routing rule for that device, includes blocking QUIC when proxied, and is matched by MAC address, so it survives a new IP. A proxy used here can’t be deleted; disabling it asks first, then returns those devices to Follow the rules'],
        ['Block a device from the hotspot, or unblock it', '"Devices" table \u2192 the toggle switch in that device\u2019s Blocked column (confirmation required \u2014 briefly reconnects the whole access point, dropping every other device too) \u2014 a blocked device stays listed (as Offline/Blocked) so it can be found and unblocked later'],
        ['Back up the current configuration', '"Backup & Restore" \u2192 "Export configuration" \u2014 downloads everything configured on the panel as one JSON file: proxy profiles, pattern rules with the default, Proxied Lookups and leak guard settings, the bypass range, email alert settings, and device nicknames, routing and blocks (includes proxy and SMTP passwords in plain text; store it securely)'],
        ['Restore or clone a configuration', '"Backup & Restore" \u2192 choose a previously exported file, "Import configuration" (confirmation required) \u2014 checks the whole file, then replaces all of the above; files from before alerts/device names existed still import and leave those as they are; if the blocked devices change, the hotspot briefly reconnects every device. The Wi-Fi SSID/passphrase are not included'],
        ['Turn a disabled proxy back on, with what it switched off', '"Proxy Profiles" \u2192 its Enabled toggle \u2014 asks whether to switch back on the rules and devices that were switched off with it (only those not changed since); Cancel enables just the profile'],
        ['Reboot the whole box (not just the Wi-Fi radio)', '"System" \u2192 "Reboot Server" button (confirmation required) \u2014 the panel and all hotspot traffic are unreachable for about a minute; everything comes back up on its own, no manual step needed'],
        ['See how much traffic each connected device has sent/received', '"Devices" table \u2014 Sent/Received columns update automatically every few seconds for online devices; these are live session counters (reset on reboot or when a device reconnects), not a historical log'],
        ['Find out which hostnames a site, app or video really uses (to write the right rule)', '"DNS Lookups" page (or the "lookups" link next to a device on the Devices page) \u2014 every name each device looked up recently, newest first, with where its traffic goes right now (the matching rule, or the default). Filter by device, by route ("Only going Direct" is the useful one when something should be proxied) and by text. "New rule" opens the Add Routing Rule form pre-filled with a suggested pattern (the whole site, e.g. *.netrw.it, or just the exact hostname under shared CDNs such as akamaized.net) and the opposite of the current route. "Add to rule" instead opens an existing rule’s Edit form with a pattern for that name appended, written for the rule’s mode, and warns if an earlier rule would still win. Either way nothing is saved until you press Save Rule. A red "Also asked \u2026 directly" note means the device sent that lookup to an outside DNS server, which pattern rules can\u2019t see (typically a phone\u2019s Private DNS or a browser\u2019s secure DNS set to a specific provider). Kept in memory only, 300 names per device, cleared on restart'],
        ['Check how strong each connected device\u2019s Wi-Fi signal is', '"Devices" table \u2192 Signal column \u2014 signal bars plus the reading in dBm (closer to 0 is stronger) as heard by the hotspot, refreshed every few seconds: Excellent (-50 or better), Good (to -60), Fair (to -70), Weak (below -70). A Weak device will be slow or drop out whatever the proxy is doing, so move it closer first'],
        ['Open this guide from the panel itself, or check which version is running', '"Help" page \u2192 "Open the Wi-Fi Proxy Hotspot Guide (PDF)" \u2014 opens this PDF, deployed onto the box alongside the panel at install time, so it works even without internet access; the version and build date shown below it are read from pyproject.toml at install time, so they always match what\u2019s actually running'],
        ['See the credits, license and disclaimer', '"Help" page \u2014 the author (Gerry Dassi), the open-source projects it is built on (redsocks, Flask, gunicorn, dnspython, python-qrcode, NetworkManager, iptables/ipset), the full MIT license text and the disclaimer (see Section 11)'],
    ],
    col_ratios = [0.55, 0.45],
)
b.body(
    'Every section above also has a small (?) help icon opening a short in-panel explanation with '
    'examples \u2014 the Routing Rules one covers all three pattern modes in detail, mirroring '
    'Section 2.1 of this guide.'
)
b.body('Every saved profile is always reachable; the "Default Behaviour" section and each pattern rule\u2019s Action dropdown are the only places that determine which traffic actually uses which profile at a glance.')
b.body(
    'The per-device traffic counters are deliberately built on plain iptables byte counters rather '
    'than any packet-capture or per-connection logging approach, specifically because a Pi 3B+ has '
    'little CPU to spare: each connected device gets exactly one counting rule in each of two '
    '`mangle`-table chains (upload, hooked from `PREROUTING`; download, hooked from `POSTROUTING`), '
    'and the kernel is already touching every packet these chains see regardless \u2014 the counters '
    'add a rule-table lookup and an integer increment, not new work. The admin panel reads those '
    'counters (a single `iptables -L` call per direction) roughly every 5 seconds while the page is '
    'open; it does not run a background collector, so closing the browser tab stops the polling '
    'entirely. Counting happens before any REDSOCKS redirect decision (upload) or from wherever the '
    'reply actually originates (download), so direct and proxied traffic are both counted correctly '
    'without needing to know which path a given connection took. These counters are intentionally '
    'not wired into `netfilter-persistent` and do not survive a reboot \u2014 unlike the REDSOCKS chain '
    '(Step 11), that is the right choice here: they are live session statistics, rebuilt fresh and '
    'cheaply by the admin panel itself the next time it renders, not policy state anything else '
    'depends on.'
)
b.body(
    'Enabling/disabling the hotspot and blocking/unblocking a device both build on the same '
    'NetworkManager mechanics already used for SSID/passphrase changes: "Disable Hotspot" sets '
    'the `Gateway-AP` connection’s `connection.autoconnect` to no and brings it down, so it '
    'stays off across a reboot until explicitly re-enabled, rather than just being down until the '
    'next boot; "Enable Hotspot" reverses both. Blocking a device adds its MAC address to that '
    'same connection’s `802-11-wireless.mac-address-denylist` property (the standard '
    'NetworkManager equivalent of hostapd’s MAC ACL) and reactivates the connection — '
    'reactivation is necessary both to force-disconnect a device that’s already associated and '
    'to make an unblock take effect, the same reason SSID/passphrase changes reactivate. Every '
    'known device (from `devices.json`, keyed by MAC) is shown on the Devices page regardless of '
    'whether it is currently online, specifically so a blocked device stays visible and can be '
    'unblocked later even though it can no longer reconnect to show up as "live."'
)
b.body('Useful command-line checks if something needs deeper investigation:')
b.code(
    'sudo systemctl status redsocks rasp-proxy-admin rasp-proxy-dns-router\n'
    'sudo journalctl -u rasp-proxy-admin --since "1 hour ago"\n'
    'sudo journalctl -u rasp-proxy-dns-router --since "1 hour ago"\n'
    'sudo iptables -t nat -L REDSOCKS -n -v\n'
    'sudo ipset list -n\n'
    'nmcli device status\n'
    'sudo iw dev wlan0 station dump\n'
    'nmcli -t -f NAME connection show --active           # is Gateway-AP currently enabled?\n'
    'nmcli -g 802-11-wireless.mac-address-denylist connection show Gateway-AP   # currently blocked MACs'
)

# ── 6. User Guide ─────────────────────────────────────────────────────────
b.section('6', 'User Guide \u2014 Connecting a Device')
b.body('For anyone connecting a phone, laptop, or other device to this hotspot:')
b.bullets([
    'Join the Wi-Fi network using the SSID and passphrase given to you by the administrator, exactly as you would any other Wi-Fi network.',
    'Once connected, your device works normally \u2014 web browsing, apps, streaming \u2014 with no extra setup on your end.',
    'By default, your internet traffic is either routed through an upstream proxy chosen by the administrator (so websites will see the proxy\u2019s address rather than this network\u2019s address) or sent direct, depending on how the administrator has configured this hotspot.',
    'Devices and services on the administrator\u2019s internal network (printers, file shares, internal tools, etc., within the configured bypass range) remain directly reachable, as if you were on that network normally.',
    'The administrator may also route specific websites differently from everything else (e.g. sending a particular streaming or banking site direct instead of through the proxy) \u2014 you do not need to do anything for this; it happens automatically based on which site you visit.',
])
b.body('To confirm the proxy is active, visit any "what is my IP" site from a connected device and check that the address shown matches the upstream proxy\u2019s address, not your own.')
b.note('If a page fails to load or is very slow, it may be the upstream proxy itself being unreachable or overloaded \u2014 report this to the administrator rather than trying to change any settings on the hotspot, which is managed centrally.')

# ── 7. Security Notes ─────────────────────────────────────────────────────
b.section('7', 'Security Notes')
b.bullets([
    'The admin web panel runs as an unprivileged, dedicated system account (proxyadmin-svc), never as root. It can only perform the exact, narrowly-scoped root actions listed in Section 4.2 Step 8 \u2014 nothing else \u2014 via sudo.',
    'Logging into the panel uses your real Linux account password, checked via PAM through a small root-owned helper (required because Linux\u2019s standard unix_chkpwd utility refuses to check another user\u2019s password from an unprivileged process). The password is passed to that helper over stdin, never as a command-line argument, so it never appears in `ps` output or in sudo\u2019s own logs.',
    'The panel is served over HTTPS with a self-signed certificate specifically so that Linux login credentials are not sent in clear text on the network \u2014 accept the browser warning, it is expected for a self-signed cert, but do not disable certificate checking generally on your own devices for other sites.',
    'The panel listens only on the wired/management interface\u2019s address, never on the hotspot\u2019s own Wi-Fi subnet. Devices on the hotspot can still connect to that address, as they can to SSH on the box: there is no inbound filter on the Wi-Fi side, so both rely on the Linux login. Use strong passwords.',
    'The upstream proxy\u2019s credentials and the hotspot passphrase are stored in plain text in root-readable configuration files on the box (`/etc/redsocks.conf`, the NetworkManager connection profile) \u2014 normal practice for this class of appliance, but worth knowing if the box\u2019s disk is ever removed or imaged.',
    'The DNS pattern-router runs as its own unprivileged account with only the CAP_NET_ADMIN Linux capability (granted via systemd, not sudo) \u2014 enough to manage ipsets and nothing else. It is on the hot path of every DNS query for the hotspot, so it is designed to fail open: any internal error just forwards the query unmatched rather than blocking DNS resolution, and it restarts automatically on crash.',
    'Every saved proxy profile\u2019s redsocks port listens on 0.0.0.0 (all interfaces), not just loopback \u2014 unchanged from the original single-proxy design, but worth knowing now that several profiles with different credentials can exist at once: anything able to reach the box directly on the wired/management side could, in principle, connect straight to a profile\u2019s port and relay through it, bypassing the hotspot entirely. This is only reachable from your own internal network, not the internet, given the existing firewall and NAT setup.',
])
b.note(
    'The panel has no login rate-limiting or lockout. Consider adding fail2ban (or an equivalent) '
    'watching its access log if the box is reachable from an untrusted network segment.'
)

# ── 8. Troubleshooting Reference ─────────────────────────────────────────────
b.section('8', 'Troubleshooting Reference')
b.body('Issues encountered building and hardening the reference deployment, kept here so they are recognised quickly if they recur:')
b.table(
    headers = ['Symptom', 'Cause', 'Fix'],
    rows = [
        ['The hotspot never starts (wlan0 shows "unavailable"), or the panel offers no 5 GHz channels', 'No Wi-Fi country (regulatory domain) set: on Raspberry Pi OS the radio stays rfkill-blocked until one is, and elsewhere the radio falls back to the most restrictive "world" channel rules', 'Set the country as in Section 3.2, `sudo rfkill unblock wifi`, then re-activate the hotspot (Wi-Fi Access Point \u2192 Restart Wi-Fi, or `sudo nmcli connection up Gateway-AP`)'],
        ['Static IP change on the wired interface silently doesn\u2019t take effect', 'A second, auto-created NetworkManager profile for the same interface was still active', 'Disable autoconnect on the stray profile, then `nmcli connection up` the correct one'],
        ['Admin panel login always rejected, even with the correct password', 'unix_chkpwd (used by PAM) refuses to verify another user\u2019s password from a non-root process', 'Run the actual PAM check in a small root-owned helper via a scoped sudo rule (see Step 8)'],
        ['Web panel shows literal "{ip}", "{port}" etc. instead of real values', 'Template used Python-style `{}` placeholders inside a Jinja2 template string', 'Use Jinja2 `{{ }}` syntax throughout render_template_string calls'],
        ['Panel shows the redsocks local proxy port/0.0.0.0 instead of the real upstream address', 'Config parser regex matched "ip"/"port" inside "local_ip"/"local_port" (substring match)', 'Anchor the regex with `\\b` word boundaries'],
        ['A sudo-invoked helper command fails with "command not found"', 'Wrong absolute path assumed (e.g. /usr/bin/iptables vs the real /usr/sbin/iptables)', 'Confirm the real path with `which <cmd>` before writing the sudoers rule'],
        ['Connected-devices list is empty despite a device being associated', 'DHCP lease file\u2019s parent directory (/var/lib/NetworkManager) is root-only (700)', 'Grant read access to that one file only via a scoped sudoers `cat` rule, not broader directory permissions'],
        ['Saving the very first proxy profile fails on a fresh install', '/var/lib/rasp-proxy-admin does not exist yet, and the unprivileged app cannot create a new directory directly under /var/lib', 'Pre-create the directory, owned by the service account, during install (see Step 7a)'],
        ['A confirm() dialog on a button silently never appears; the action just happens', 'A literal `\\"` was used inside a plain (non-f, non-raw) Python triple-quoted string to escape a quote for the onclick attribute \u2014 Python collapses that to a bare `"` *before* Jinja2 ever sees it, which then prematurely closes the `onclick="..."` attribute in the rendered HTML', 'Avoid nesting the same quote character across Python string literals, Jinja2 output and inline JavaScript; use single quotes for the JS string inside a double-quoted HTML attribute, or vice versa, with no escaping needed'],
        ['A pattern rule with a "proxy" action fails to save with "Need TCP, UDP, SCTP or DCCP with port specification"', 'REDIRECT --to-ports needs an explicit -p tcp on that specific iptables rule; it is not inherited from the chain', 'Add -p tcp to any rule that targets REDIRECT, not just the chain\u2019s catch-all'],
        ['A device briefly gets unrestricted, un-proxied internet access mid-change', 'The firewall-rebuild helper flushes the REDSOCKS chain before re-adding rules; if it errors out partway through (e.g. the bug above), the catch-all redirect is missing until the next successful rebuild', 'Treat any rebuild-helper failure as urgent \u2014 re-run it immediately rather than leaving the chain partially built; consider this when testing new rule types'],
        ['Traffic that should go through a specific proxy goes direct instead, with no error shown', 'The default or a pattern rule names a proxy profile that no longer exists (deleted via manual JSON edit, bypassing the panel\u2019s own guard)', 'The panel shows "(missing)" next to the stale reference in the pattern-rules table; point it at a real profile or Direct and save'],
        ['`ipset list` accumulates sets no longer used by any rule', 'Deleting a pattern rule removes its firewall reference but not its ipset on its own', 'Not user-visible or harmful in normal use \u2014 the rebuild helper prunes any wpx_* set unused by the current rule list on every rebuild, so this self-corrects the next time anything changes'],
        ['After a reboot, ALL hotspot traffic goes out direct and un-filtered \u2014 the REDSOCKS chain and every pattern rule silently vanish, with no error anywhere', '`netfilter-persistent` persists saved iptables rules but never `ipset` contents; `iptables-restore` applies its saved ruleset as one atomic transaction, so a single restored rule referencing a since-vanished ipset (which never survives a reboot) aborts the *entire* restore, leaving no custom rules at all \u2014 not just the one broken rule', 'Rebuild the whole REDSOCKS chain and its ipsets from the authoritative pattern_rules.json on every boot, before anything relies on it \u2014 see Step 11\u2019s rasp-proxy-firewall-init.service; if migrating a box built before this existed, check `systemctl is-enabled rasp-proxy-firewall-init` explicitly'],
    ],
    col_ratios = [0.32, 0.34, 0.34],
)
b.note(
    'On Raspberry Pi OS Legacy/Bullseye (dhcpcd + hostapd + dnsmasq instead of NetworkManager), the '
    'static IP goes in /etc/dhcpcd.conf, the access point is configured via /etc/hostapd/hostapd.conf '
    'and /etc/dnsmasq.conf, and manual iptables MASQUERADE/FORWARD rules are required since there is '
    'no NetworkManager "shared" method to provide them automatically. The redsocks and firewall-bypass '
    'steps in Section 4.2 are unchanged either way.'
)
b.warning('DNS lookups are not intercepted by redsocks (it only handles TCP), so they leave via normal routing rather than through the proxy \u2014 a device\u2019s DNS queries can reveal its browsing targets even while its actual connections are proxied. Treat the proxy as traffic-routing, not full anonymisation.')

# ── 9. Reference ─────────────────────────────────────────────────────────
b.section('9', 'Reference')
b.table(
    headers = ['Item', 'Location'],
    rows = [
        ['redsocks config (one block per saved profile, regenerated on every change)', '/etc/redsocks.conf'],
        ['Saved proxy profiles, each with its own permanent local port (from 20000)', '/var/lib/rasp-proxy-admin/proxies.json'],
        ['Internal bypass CIDR + global default (direct, or a profile name) + saved routing rules, in priority order — the single source of truth the firewall is rebuilt from', '/var/lib/rasp-proxy-admin/pattern_rules.json'],
        ['Admin web app', '/opt/rasp-proxy-admin/app.py'],
        ['DNS pattern-router daemon', '/opt/rasp-proxy-admin/dns_router.py'],
        ['This guide (served by the panel’s Help page)', '/opt/rasp-proxy-admin/Wi-Fi-Proxy-Hotspot-Guide.pdf'],
        ['PAM check helper', '/usr/local/sbin/rasp-proxy-pamcheck'],
        ['Firewall rebuild helper (bypass CIDR + pattern rules + catch-all; also runs at boot)', '/usr/local/sbin/rasp-proxy-rebuild-firewall'],
        ['PAM service definition', '/etc/pam.d/rasp-proxy-admin'],
        ['TLS certificate/key', '/etc/rasp-proxy-admin/tls/'],
        ['Sudoers rule', '/etc/sudoers.d/proxyadmin-svc'],
        ['Admin panel systemd unit', '/etc/systemd/system/rasp-proxy-admin.service'],
        ['DNS router systemd unit', '/etc/systemd/system/rasp-proxy-dns-router.service'],
        ['Boot-time firewall rebuild systemd unit', '/etc/systemd/system/rasp-proxy-firewall-init.service'],
        ['dnsmasq forwarding to the DNS router', '/etc/NetworkManager/dnsmasq-shared.d/pattern-routing.conf'],
        ['Per-rule IP sets (tagged by the DNS router)', 'ipset, named wpx_<rule id>'],
        ['DHCP lease file (hotspot side)', '/var/lib/NetworkManager/dnsmasq-<ap-iface>.leases'],
        ['Firewall chain', 'iptables nat table, chain REDSOCKS'],
        ['Per-device traffic-accounting helper (adds/removes one counter rule per connected device)', '/usr/local/sbin/rasp-proxy-traffic-sync'],
        ['Per-device traffic counters (upload/download; not persisted across reboot by design)', 'iptables mangle table, chains WPXACCT_UP / WPXACCT_DOWN'],
        ['Every known device ever seen (MAC, hostname, first/last seen, blocked)', '/var/lib/rasp-proxy-admin/devices.json'],
        ['Hotspot on/off state (survives reboot) and per-device block list', "Gateway-AP connection's connection.autoconnect and 802-11-wireless.mac-address-denylist properties (nmcli)"],
        ['Shared modules (rule matching, proxy check, DNS-over-HTTPS through a proxy, email sending)', '/opt/rasp-proxy-admin/pattern_match.py, proxy_check.py, proxy_doh.py, mailer.py'],
        ['DNS Lookups snapshot (RAM only, cleared on restart)', '/run/rasp-proxy-dns/lookups.json'],
        ['Health check helper, and its every-2-minutes timer', '/usr/local/sbin/rasp-proxy-health; /etc/systemd/system/rasp-proxy-health.service and .timer'],
        ['Latest health results (read by the Overview page; RAM only)', '/run/rasp-proxy-health/status.json'],
        ['Health alert state: debounce and recovery counters, unsent or held alert emails, last known proxy exit IPs', '/var/lib/rasp-proxy-admin/health_state.json (root, 0600)'],
        ['Email alert settings, including the SMTP password', '/var/lib/rasp-proxy-admin/alerts.json (0600)'],
    ],
    col_ratios = [0.4, 0.6],
)

# ── 10. Rollback / Uninstall ─────────────────────────────────────────────
b.section('10', 'Rollback / Uninstall')
b.body('From the package folder, as root:')
b.code('sudo ./uninstall.sh')
b.body(
    'This removes the admin panel, the DNS pattern-router, both service accounts and the sudoers '
    'rule, the redsocks config, the firewall rules and any pattern-rule ipsets, and the hotspot '
    'connection. It deliberately leaves the wired interface\u2019s static IP and the installed packages '
    '(redsocks, iptables-persistent, python3-flask, python3-pam, gunicorn, iw, python3-dnspython, python3-qrcode, '
    'ipset, dnsmasq-base, openssl) in place, as well as a patched /usr/sbin/redsocks if Step 4b '
    'succeeded (reinstall the redsocks package to restore the stock binary); revert those manually '
    'if a full teardown is needed.'
)

# ── 11. License, credits and disclaimer ─────────────────────────────────────
b.section('11', 'License, Credits and Disclaimer')
b.body('<b>License</b>')
b.body(
    'Wi-Fi Proxy Hotspot is released under the <b>MIT License</b>, Copyright (c) 2026 Gerry Dassi. '
    'The full license text is in the LICENSE file of the repository and on the admin panel’s '
    'Help page.'
)
b.body('<b>Disclaimer</b>')
b.warning(
    'This software is provided "as is", without warranty of any kind. It is a personal project: '
    'it is not regularly maintained and no support is guaranteed. You are responsible for '
    'complying with the laws of your country, the policies of the network you connect it to, and '
    'the terms of service of your proxy provider and of any services you reach through it '
    '(for example geo-restricted streaming services).'
)
b.body('<b>Credits</b>')
b.body('The project is built on, and would not exist without, these open-source projects:')
b.table(
    headers = ['Project', 'Used for', 'License'],
    rows = [
        ['redsocks', 'Transparent TCP-to-proxy redirector (one instance, one block per proxy profile)', 'Apache-2.0'],
        ['Flask', 'Admin panel web framework', 'BSD-3-Clause'],
        ['gunicorn', 'HTTPS server running the admin panel', 'MIT'],
        ['dnspython', 'DNS handling in the DNS pattern-router', 'ISC'],
        ['python-qrcode', 'Wi-Fi join QR code', 'BSD'],
        ['NetworkManager', 'Wired configuration, Wi-Fi access point, DHCP, NAT', 'GPL-2.0+'],
        ['iptables / ipset', 'Firewall chains, traffic redirection, per-rule IP sets, traffic counters', 'GPL-2.0'],
        ['ReportLab (documentation only)', 'Generating this PDF guide', 'BSD'],
    ],
    col_ratios = [0.25, 0.55, 0.20],
)
b.body(
    'The two redsocks performance patches in package/redsocks-patches/ (Step 4b) are '
    'modifications of redsocks and are distributed under redsocks’ own Apache-2.0 license, not '
    'the MIT license covering the rest of the project.'
)

b.build()
print('Written to', OUT)

# The installer deploys this PDF onto the box (package/install.sh, Step 7) so
# the admin panel's Help page works with no internet access, so package/
# needs its own up-to-date copy alongside app.py, not a live fetch from docs/.
import shutil
PACKAGE_COPY = os.path.join(os.path.dirname(_HERE), 'package', 'Wi-Fi-Proxy-Hotspot-Guide.pdf')
shutil.copyfile(OUT, PACKAGE_COPY)
print('Copied to', PACKAGE_COPY)
