"""
The admin panel's (?) help texts, as HTML fragments passed to the
templates (see templates/macros.html). Plain strings, not templates.
"""

HELP_PROXY_PROFILES = """
<h3>Proxy Profiles</h3>
<p>Each profile is a saved upstream proxy (HTTP or SOCKS5) with its own address and login
credentials. Add as many as you like — every profile gets its own permanent connection and
stays available to be picked by name in <b>Default Behaviour</b> or any <b>Routing Rule</b>.</p>
<p>There is no single "active" profile any more: how a profile is used is entirely decided by
what points at it — the global default, or a specific rule.</p>
<p>A profile can't be deleted while something still points at it; you'll be told exactly what to
change first.</p>
<p>The <b>Enabled</b> switch is for a proxy you don't always have running, such as a test proxy you
start up now and then. A disabled profile:</p>
<ul>
<li>isn't health-checked on the Overview page and never triggers an email alert;</li>
<li>takes its rules with it: every <i>active</i> routing rule that uses it is switched off too,
after you confirm, so no traffic keeps going through a proxy nobody is watching;</li>
<li>can't be the Default Behaviour: point the default somewhere else first;</li>
<li>stays saved, shows "(disabled)" in the Action lists, and still works with its <b>Check</b>
button.</li>
</ul>
<p>Enabling it again brings back its health checks, and asks whether to switch back on the rules and
devices that were switched off with it. Only those still unchanged are offered: a rule now pointing
elsewhere, or a device you've since set differently, is left alone. Say Cancel to enable just the
profile and pick what comes back yourself.</p>
"""

HELP_WIFI = """
<h3>Wi-Fi Access Point</h3>
<p>The network name (SSID) and password devices use to join this hotspot.</p>
<p>Changing either — or clicking <b>Restart Wi-Fi</b> — briefly disconnects any device currently
connected, which will need to rejoin (with the new details, if you changed them).</p>
<p><b>Disable Hotspot</b> turns the Wi-Fi radio off entirely: it stops broadcasting, immediately
disconnects every device, and — unlike a reboot of anything else on this box — stays off even
across a reboot of the whole server, until you come back here and click <b>Enable Hotspot</b>.
Saved SSID/passphrase changes are kept either way, so you can update them while disabled and
they'll be in place the next time you turn it back on.</p>
<p><b>Band</b> shows which Wi-Fi band the hotspot is actually broadcasting on right now (read from
the radio itself when the hotspot is enabled, or from the saved configuration when it's off). A
single Wi-Fi radio in access-point mode broadcasts one band at a time, not both simultaneously,
even on hardware that supports 5 GHz.</p>
<p><b>Band &amp; channel</b> moves the hotspot. <b>5 GHz</b> is usually much faster and less crowded,
which helps streaming. It reaches less far through walls, and devices that only support 2.4 GHz
(some older phones, smart plugs, many TVs) can't see it at all. The list only offers channels this
radio reports it may start a hotspot on in your country (its regulatory domain): channels that need
radar detection (DFS) or aren't allowed are left out. If no 5 GHz choice appears, the box's Wi-Fi
country probably isn't set (see the guide). "Automatic" lets the radio choose; on 2.4 GHz, 1, 6 or
11 avoid overlapping neighbours. Every device drops for a few seconds when
you apply a change. If the hotspot can't start on the new setting, it goes back to the previous one
by itself and tells you.</p>
"""

HELP_INTERNAL_NETWORK = """
<h3>Internal Network</h3>
<p>Devices connected to this hotspot can always reach this address range directly, bypassing the
proxy entirely — use it for your own home/office network (printers, file shares, this box's own
management address, etc.) that hotspot devices need normal access to.</p>
<p>This always wins over the default and every pattern rule below it.</p>
"""

HELP_DEFAULT_BEHAVIOUR = """
<h3>Default Behaviour</h3>
<p>What happens to hotspot traffic that isn't covered by the Internal Network range above, or by
any matching Routing Rule below: send it <b>Direct</b> (no proxy), or through one of your
saved Proxy Profiles.</p>
<p>Example: set this to Direct, then add one pattern rule sending a specific site through a proxy
profile — everything else goes straight out, only that one site is proxied.</p>
"""

HELP_PATTERN_RULES = """
<h3>Routing Rules</h3>
<p>Rules are checked <b>in order, top to bottom</b> — the first one that matches a hostname wins,
and overrides Default Behaviour for just that domain. Use Move Up/Down to reorder them.</p>
<p>A rule can hold <b>several patterns</b>, one per line, and matches a hostname if any of them
does. One rule then covers a whole service with one switch, e.g. RaiPlay's site plus its live-stream
CDNs. <b>Start from a preset</b> (in Add Routing Rule) fills in services whose hostnames have been
checked on this box. For anything else, find the real hostnames on the DNS Lookups page.</p>
<p><b>Test a hostname</b> (above the table) shows exactly what would happen to a name: which rule
wins and through which pattern, later rules it hides, switched-off rules that would have matched, and
whether the lookup goes through the proxy. You can paste a full URL.</p>
<p><b>Activity</b> shows recent lookups that each rule matched (from DNS Lookups), and how many
connections its firewall entry has handled since the rules last changed (updated every 2 minutes).
"No activity yet" on a rule you expected to be busy usually means its patterns don't match the names
the service really uses.</p>
<p>Each rule's patterns share one <b>Mode</b> that says how to interpret them. Patterns match
<b>hostnames only</b>, as a device looks them up, never full URLs, paths or ports:
<code>*.discoveryplus.com</code> works, <code>*.discoveryplus.com/*</code> can never match (the panel
now refuses it).</p>
<ul>
<li><b>Exact match</b> — the hostname must equal the pattern exactly. Example: pattern
<code>raiplay.it</code> matches only <code>raiplay.it</code> itself, not
<code>www.raiplay.it</code>.</li>
<li><b>Wildcard</b> — <code>*</code> matches any run of characters, <code>?</code> matches exactly
one. Example: pattern <code>*.raiplay.it</code> matches <code>www.raiplay.it</code> and
<code>player.raiplay.it</code>, but <b>not</b> the bare <code>raiplay.it</code> — add a second
Exact match rule for that if you need both.</li>
<li><b>Regular expression</b> — full pattern matching against the <b>whole</b> hostname, not just
part of it. Example: <code>^(.*\\.)?raiplay\\.it$</code> matches both <code>raiplay.it</code> and
every subdomain of it, in a single rule.</li>
</ul>
<p>Each rule's <b>Action</b> is Direct or any saved Proxy Profile — completely independent of
Default Behaviour and of every other rule, so different sites can go through different proxies
at the same time.</p>
<p><b>Enable/Disable</b> temporarily switches a rule off without deleting it — a disabled rule is
skipped entirely, as if it weren't there, so matching traffic just falls through to the next rule
or the default. Handy for testing or ruling something out without losing the rule's settings; the
row is shown greyed out with a Disabled status while it's off.</p>
<p><b>When a change takes effect:</b> adding, editing, enabling or disabling a rule reaches devices
that are already connected within about a minute, for new connections. Something already
streaming keeps its existing connection, so reload the video or app if it doesn't pick the change
up by itself.</p>
<p><b>Worth knowing:</b> this only catches domains actually looked up through this hotspot's own
DNS. A device using its own DNS-over-HTTPS, or a hardcoded resolver, will silently skip matching
and just get the default behaviour instead.</p>
"""

HELP_DEVICES = """
<h3>Devices</h3>
<p>Every device that has ever joined this hotspot, not just the ones currently connected —
hostname (if known), IP address, MAC address, and status (Online, Offline, or Blocked). Click
<b>Refresh</b> to update live status (e.g. after a device joins or leaves).</p>
<p><b>Sent</b> and <b>Received</b> are each online device's total traffic, counted directly by the
firewall (no extra load on the box) and updated automatically every few seconds without needing
Refresh. These are live session counters, not a historical log — they reset if the device
disconnects and rejoins, or after a reboot.</p>
<p><b>Block</b> stops a device from using the hotspot at all — it can no longer associate with the
Wi-Fi, even if it knows the password. <b>Unblock</b> reverses this. Both briefly reconnect the
whole Wi-Fi access point to take effect, which drops every other connected device too (they
reconnect on their own). A blocked device stays listed as Offline/Blocked so it's easy to find and
unblock later, even while it can't get back online to show up as "live."</p>
<p><b>Name it / rename</b> gives a device a nickname (hostnames are often blank or cryptic). It's
used everywhere the device appears, including DNS Lookups.</p>
<p><b>Routing</b> overrides the Routing Rules for one device: <b>Follow the rules</b> (the
default), <b>Always direct</b>, or <b>Always through</b> a chosen proxy, e.g. a TV box that should
always appear to be in the proxy's country. It applies to everything the device does, and QUIC is blocked for it when
proxied so nothing slips out over HTTP/3. Devices are recognised by their MAC address, so this
survives a new IP address. A phone that uses a different "private" MAC per network keeps the same
one for this hotspot unless you reset it. A proxy used here can't be deleted, and disabling it
returns these devices to Follow the rules (after asking).</p>
<p><b>Signal</b> is how strongly the hotspot hears each online device, in dBm (closer to 0 is
stronger), read live from the Wi-Fi radio and refreshed every few seconds. As a rough guide:
<b>Excellent</b> -50 or better, <b>Good</b> down to -60, <b>Fair</b> down to -70, <b>Weak</b>
below that. A Weak device will see slow or dropping connections whatever the proxy is doing, so
moving it closer is the first thing to try.</p>
"""

HELP_OVERVIEW = """
<h3>Overview</h3>
<p>The health of the whole box at a glance, from checks that run on their own every 2 minutes
(<b>Run checks now</b> runs them straight away):</p>
<ul>
<li><b>Services</b>: redsocks, the DNS router, this panel, and the boot-time firewall setup.</li>
<li><b>Hotspot &amp; DNS</b>: the Wi-Fi hotspot and its DNS/DHCP, the pattern-rule DNS router, the DNS
Lookups capture, and whether the internet is reachable directly.</li>
<li><b>Firewall</b>: that the routing chains are complete (one rule per enabled pattern rule, plus
the bypass range and the default) and hooked in, including the QUIC guard.</li>
<li><b>Proxies</b>: every proxy profile, tested directly (the same test as its Check button), and
the public IP its traffic exits from, rechecked every 30 minutes. The country shown next to it
comes from one geolocation database (country.is), and these disagree about proxy addresses:
sites such as RaiPlay may place the same IP in a different country. So treat it as a hint. What
matters is a <i>change</i>, which is emailed as a notice.</li>
<li><b>System</b>: under-voltage (a failing power supply caused real problems on this box before),
CPU temperature, disk space and memory.</li>
</ul>
<p>Green is OK, amber needs a look, red is broken. A proxy that no rule or default uses shows amber,
not red, when it's down, and never triggers an alert. A proxy profile that's switched off
(<b>Enabled</b> on the Proxy Profiles page) shows grey: it isn't tested at all and never alerts.
That's handy for a proxy you only start up now and then.</p>
<p>A small dot next to <b>Overview</b> in the menu shows the overall state from any page.</p>
<p>Set up <b>Email Alerts</b> on the System page to be told about problems without opening this page.
Checks only ever report: nothing here changes routing.</p>
"""

HELP_ALERTS = """
<h3>Email Alerts</h3>
<p>Emails you when something on the Overview page starts failing and again when it recovers. A
problem has to show up on two checks in a row (about 4 minutes) before it's reported, so a brief
blip, such as a service restarting, doesn't wake you up. You also get one-off notices: the box
restarting (if ticked), under-voltage seen in the kernel log, and a proxy's exit IP or its
country changing (which can break geo-blocked sites).</p>
<p>If an alert can't be sent, for example because the internet itself is down, it's kept and retried
every 2 minutes, so it still arrives once the connection is back.</p>
<p><b>Gmail:</b> server <code>smtp.gmail.com</code>, port 587, STARTTLS, your Gmail address as the
username, and an <b>app password</b> (Google account → Security → App passwords), not your normal
password. <b>Outlook.com:</b> <code>smtp-mail.outlook.com</code>, port 587, STARTTLS.</p>
<p><b>Send test email</b> uses what's in the form right now, so you can check the settings before
saving them. The password is stored only on this box and is never shown again. Leave it blank to
keep the saved one.</p>
"""

HELP_LEAK_GUARDS = """
<h3>Leak Guards</h3>
<p>Routing rules work by watching the DNS lookups devices make through this hotspot. A device that
looks things up somewhere else, or uses IPv6, goes straight past them: no proxy where a rule says
proxy, and nothing on the DNS Lookups page to explain why. Each guard closes one of those gaps:</p>
<ul>
<li><b>Force all DNS through the hotspot</b>: lookups a device sends to an outside DNS server
(smart TVs and Chromecasts often use 8.8.8.8 whatever they're told) are answered by the hotspot
instead. Encrypted DNS-over-TLS (port 853, e.g. Android's Private DNS) is blocked: in
<i>Automatic</i> mode the phone quietly falls back to normal DNS. If a phone has Private DNS set to
a <i>specific provider</i>, it will say it can't connect. Set it to Automatic or Off while on this
hotspot. Firefox is also told (via its standard signal) not to switch on its own encrypted DNS.</li>
<li><b>Block iCloud Private Relay</b>: uses Apple's standard signal for networks. iPhones and Macs
show "Private Relay is turned off for this network" and work normally otherwise.</li>
<li><b>Block IPv6 from hotspot devices</b>: everything here, including the proxies, works over
IPv4, so IPv6 would bypass it all. There's no IPv6 on the hotspot today; this keeps it that way.</li>
</ul>
<p>The internal network range is never affected. Where a guard has caught something since the rules
last changed, the count is shown under it (updated every 2 minutes).</p>
"""

HELP_RESOLVE_VIA_PROXY = """
<h3>Proxied Lookups</h3>
<p>A video service's CDN picks which server to hand out from <i>where the DNS question comes
from</i>. Asked from here, it answers with a server near this box. When the proxy is in another
country, your proxied traffic then reaches that nearby server from the proxy's country and comes
all the way back, so video crosses the long link twice.</p>
<p>With this on, a hostname matched by a rule that routes through a proxy is looked up <b>through
that proxy</b> (encrypted, via Google's public DNS-over-HTTPS). The CDN then answers with a server
near the proxy. Measured on a live TV stream through a proxy on another continent: a 10-second
video segment took about 7 seconds to arrive from the server near the box (sometimes over 10, so
the player stalls) and about 3.5 from the one near the proxy.</p>
<ul>
<li>Only hostnames matched by a <b>rule</b> are affected. Everything else, including traffic that
follows a proxied Default Behaviour, uses ordinary DNS.</li>
<li>The box keeps a couple of connections open through each such proxy, so these lookups take one
round trip (about half a second). If the proxy isn't ready, the lookup uses ordinary DNS instead.
It never waits.</li>
<li>These lookups go to Google through the proxy instead of to your router's DNS.</li>
</ul>
<p>Turning it on or off clears the box's DNS cache, so it applies within about a minute. A video
that's already playing keeps its current server until it reconnects.</p>
"""

HELP_LOOKUPS = """
<h3>DNS Lookups</h3>
<p>Every hostname each hotspot device has looked up recently, newest first. It's the quickest way to
find the names a site or app really uses, which are often not the site's own domain. A live TV
stream, for example, is usually fetched from a separate video CDN (RaiPlay's live channels come from
<code>*.netrw.it</code> and <code>*.msvdn.net</code>, not <code>raiplay.it</code>).</p>
<p>To fix something that isn't working through the proxy:</p>
<ul>
<li>Pick the device, and set Route to <b>Only going Direct</b>.</li>
<li>Try the site or video on that device. New names appear here within a few seconds, with no need
to refresh.</li>
<li>Click <b>New rule</b> next to a name that belongs to the service. The rule form opens pre-filled
with a suggested pattern (the whole site, e.g. <code>*.netrw.it</code>, or just the exact hostname
under shared CDNs like <code>akamaized.net</code>, where a wildcard would catch unrelated sites).
Check the action and save.</li>
<li>Or, if the service already has a rule, pick it from <b>Add to rule</b>. That rule's Edit form
opens with the pattern added at the end of its list, written for the rule's mode (the same suggestion
for Wildcard, the exact hostname for Exact match). Check it and save. Nothing changes until you
do.</li>
</ul>
<p><b>Route now</b> is where that name's traffic goes under the current rules: the matching rule's
action, or the default. It updates as soon as you change a rule. Devices pick the change up within
about a minute.</p>
<p>A red <b>Also asked ... directly</b> note means the device sent that lookup straight to an outside DNS
server instead of this hotspot. Routing rules can't apply to such lookups. The usual cause is a
phone's Private DNS setting or a browser's secure DNS set to a specific provider.</p>
<p>Lookups are captured passively on the box and kept in memory only (the most recent 300 names per
device), never written to disk, and cleared when the box restarts.</p>
"""

HELP_BACKUP_RESTORE = """
<h3>Backup &amp; Restore</h3>
<p>Export saves everything configured on this panel as one JSON file: proxy profiles, routing
rules with the default, Proxied Lookups and leak guard settings, the internal bypass range, email
alert settings, and device nicknames, routing and blocks. It includes <b>proxy and SMTP passwords
in plain text</b>, so keep the downloaded file somewhere secure. The Wi-Fi SSID/passphrase are not
included.</p>
<p>Import replaces all of the above with the contents of a previously exported file. The whole file
is checked before anything changes. Files exported before alerts and device names existed still
import, and they leave those settings as they are. Use this to back up before a risky change, or
to move the same configuration to another box.</p>
"""

HELP_SYSTEM = """
<h3>System</h3>
<p><b>Reboot Server</b> restarts the whole Raspberry Pi, not just the Wi-Fi radio (that's the
Wi-Fi Access Point section's Restart Wi-Fi button). Everything — the hotspot, redsocks, the DNS
pattern router, and this admin panel itself — comes back up automatically on its own; there is
no manual step required afterwards.</p>
<p>The panel will be unreachable for roughly a minute while the box restarts. Use this if the
box feels stuck, after a change that needs a clean restart to fully take effect, or just to
confirm everything really does come back on its own.</p>
"""

HELP_HELP = """
<h3>Help</h3>
<p>Opens the full <b>Wi-Fi Proxy Hotspot Guide</b> as a PDF in a new browser tab — architecture,
every day-to-day task on this panel, the end-user "how do I connect a device" instructions, and a
troubleshooting reference.</p>
<p>The guide is installed on this box alongside the panel itself at install time, so it opens even
without internet access.</p>
<p>The version and build date shown below come from the project's own version file at install
time, so they always match what's actually running here.</p>
<p>Below that: who made this, where the source code lives, the open-source projects it's built on,
the license (MIT) and a disclaimer. In short, it comes with no warranty and isn't regularly
maintained.</p>
"""
