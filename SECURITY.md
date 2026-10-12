# Security

## Reporting a problem

If you find a security issue, please report it privately through GitHub's
**Security → Report a vulnerability** form on this repository, rather than
in a public issue.

This project is **not regularly maintained**, so there is no promised
response time and a fix may never come. If the issue matters to you, a pull
request with the fix (and a test) is the fastest route.

## What to know before deploying

- **Login:** the admin panel uses the box's Linux accounts through PAM, over
  HTTPS with a self-signed certificate. It has no rate limiting or lockout,
  so use strong passwords. Consider fail2ban if the wired network isn't
  trusted.
- **Reachability:** the panel listens on the wired interface's address.
  Hotspot clients can still connect to that address, and to SSH on the box,
  because there is no inbound filter on the Wi-Fi side.
- **Secrets on the box:** proxy credentials, the SMTP password and the Wi-Fi
  passphrase are stored in plain text in files readable only by root and the
  service accounts. A configuration **export** contains the proxy and SMTP
  passwords in plain text.
- **Proxy ports:** each proxy profile's redsocks port listens on all
  interfaces, so anything that can reach the box directly can relay through
  it.
- **Privileges:** the panel runs unprivileged. Its root actions are limited
  to the exact commands in `/etc/sudoers.d/proxyadmin-svc`, and the
  installer and the guide list them.
