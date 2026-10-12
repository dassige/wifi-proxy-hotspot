# Changelog

All notable changes to this project will be documented in this file.

## [1.22.0] - 2026/10/12

First public release.

- Published under the MIT License, with a full public README (purpose, hardware, step-by-step install), a disclaimer and credits.
- Help page of the admin panel now shows the author, source link, credits for the open-source projects used, the MIT license text and the disclaimer.
- Wi-Fi band & channel choices now follow the radio's regulatory domain (`iw list`) instead of a fixed country's list; channels that are disabled, passive-only or need radar detection are hidden.
- Installer: the optional redsocks patch build now works on any Debian-based release (uses the running distro's codename and whatever redsocks source version apt fetches); `dnsmasq-base` and `openssl` are installed explicitly.
- Removed deployment-specific details (addresses, host names, provider names) from code comments, tests and the guide.

## [1.21.2] - 2026/10/02

- feat: implement "Add to rule" functionality for DNS lookups, enhancing rule management

## [1.20.1] - 2026/10/01

- Refactor terminology from "URL Pattern Rules" to "Routing Rules" throughout the application

- Updated documentation in README.md and Wi-Fi-Proxy-Hotspot-Guide.pdf to reflect the change from URL Pattern Rules to Routing Rules.
- Modified code references in app.py, dns_router.py, and other related files to ensure consistency with the new terminology.
- Adjusted HTML templates and CSS styles to accommodate the updated routing rules interface.
- Updated help texts and user interface elements to replace instances of "URL Pattern Rules" with "Routing Rules".
- Ensured all related tests in test_rule_tools.py are updated to reflect the new terminology for accurate testing.

## [1.20.0] - 2026/10/01

- Add new pages for pattern rules, proxy profiles, system information, and Wi-Fi settings

- Implemented `pattern-rules.html` to manage URL pattern rules and default behavior settings.
- Created `proxy-profiles.html` for managing proxy profiles, including enabling/disabling profiles and checking their status.
- Added `system.html` to display system hardware information and manage email alert settings.
- Developed `wifi.html` for configuring Wi-Fi access point settings, including SSID and passphrase management.
- Introduced tests in `test_housekeeping.py` for backup/restore functionality and profile re-enabling logic.

## [1.19.0] - 2026/10/01

- feat: add per-device routing policies and Wi-Fi QR code generation

- Enhanced the installation script to include python3-qrcode package.
- Updated the firewall health check to account for device policies.
- Implemented device policies in the firewall rebuild process, ensuring they are prioritized correctly.
- Added tests for device policies, ensuring they are applied and validated correctly.
- Introduced functionality to generate Wi-Fi QR codes for easier hotspot access.
- Improved UI to reflect device policies and added dark mode support.

## [1.18.0] - 2026/10/01

- Implement leak guards to prevent DNS leaks and enhance privacy

- Added leak guards to block plain DNS, DNS-over-TLS, and IPv6 traffic from bypassing the hotspot's proxy rules.
- Introduced a new configuration option for leak guards in the application settings.
- Updated the firewall rebuild process to include rules for leak guards.
- Enhanced the DNS router to respond with NXDOMAIN for blocked queries.
- Implemented health checks for leak guards to ensure they are correctly configured and functioning.
- Added tests to verify the functionality of leak guards and their integration with existing systems.
- Updated user documentation to reflect changes in leak guard functionality and configuration.

## [1.17.0] - 2026/10/01

- Refactor pattern matching to support multi-pattern rules and enhance rule handling

- Updated `pattern_match.py` to allow rules to contain multiple patterns, improving flexibility in matching hostnames.
- Introduced `rule_patterns` function to handle extraction of patterns from rules.
- Enhanced `prepare_rule` to compile multiple regex patterns and store them for matching.
- Modified `matching_pattern` to return the first matching pattern from a rule.
- Updated `match_rule` to utilize the new matching logic.
- Adjusted `rasp-proxy-health.py` to read connection counts for each pattern rule.
- Reflected changes in tests across `test_app_logic.py`, `test_app_render.py`, and added new tests in `test_rule_tools.py` to ensure comprehensive coverage of multi-pattern functionality.

## [1.16.1] - 2026/10/01

- Implement DNS-over-HTTPS (DoH) support through upstream proxies

- Added proxy_doh.py to handle DNS-over-HTTPS requests through configured proxies.
- Integrated DoH functionality into dns_router.py, allowing proxied lookups to resolve hostnames via the proxy.
- Enhanced load_rules function to manage DoH tunnels and synchronize proxy profiles.
- Updated proxy_check.py to support tunnel requests through the proxy.
- Modified rasp-proxy-health.py to include health checks for proxied lookups.
- Added tests for DoH functionality and its integration with dns_router.
- Updated install.sh to include the new proxy_doh.py script.

## [1.16.0] - 2026/10/01

- Add comprehensive test suite for DNS router, health checks, mailer, proxy checks, firewall rebuild, and repo consistency

- Introduced tests for DNS router functionality including tagging, response handling, and query parsing.
- Implemented health check tests to validate alerting state machine and proxy configurations.
- Added mailer tests to ensure email alerts are sent correctly and sensitive information is not leaked.
- Created proxy check tests to verify HTTP and SOCKS5 proxy behaviors and error handling.
- Developed tests for firewall rebuild logic to ensure correct iptables rules are applied and maintained.
- Added repository consistency tests to ensure installation scripts and deployment manifests are in sync.

## [1.15.0] - 2026/10/01

- feat: Implement deployment script and enhance service management for Wi-Fi Proxy Hotspot

## [1.14.0] - 2026/10/01

- Add health check and email alert functionality for Wi-Fi Proxy Hotspot

- Implemented a periodic health check service (rasp-proxy-health) that runs every 2 minutes to monitor the status of the Wi-Fi Proxy Hotspot, including services, firewall rules, DNS functionality, and proxy profiles.
- Introduced email alerting for health check failures and recoveries, with configuration stored securely.
- Added proxy_check.py for direct checks of upstream proxy profiles, ensuring accurate connectivity and latency measurements.
- Created mailer.py to handle SMTP settings and email sending, ensuring sensitive information is not exposed.
- Updated install.sh to include new scripts and systemd services for health checks and email alerts.
- Enhanced uninstall.sh to properly remove new services and files related to health checks and email alerts.

## [1.13.0] - 2026/10/01

- Implement DNS Lookups feature with pattern matching and admin panel integration

- Added a new DNS Lookups page to the admin panel, displaying recent hostname lookups by devices.
- Introduced functions to suggest pattern rules based on looked-up names, considering shared CDN domains and second-level labels.
- Enhanced the DNS router to capture and store DNS queries from devices, allowing for passive monitoring of lookups.
- Created a new module `pattern_match.py` for shared rule matching logic between the DNS router and the admin panel.
- Updated the app and router to handle new lookup data, including automatic updates and filtering options in the UI.
- Modified installation scripts to include the new pattern matching module and adjusted service capabilities for DNS query capture.

## [1.12.1] - 2026/10/01

- feat: Improve DNS handling and rule update responsiveness in hotspot configuration

## [1.12.0] - 2026/10/01

- feat: Enhance mobile layout and Wi-Fi signal display

- Implemented a mobile-friendly layout for the admin panel, including a sticky tab menu and responsive tables.
- Added a new Signal column to the Devices table, displaying Wi-Fi signal strength in dBm with visual indicators.
- Introduced a new API endpoint (/api/signal) to fetch real-time signal data for connected devices.
- Updated the documentation to reflect changes in the user interface and new features.
- Improved the uninstall script to remove QUIC-related iptables rules and chains.

## [1.11.4] - 2026/09/30

- Add proxy profile connectivity check and system hardware info display

## [1.11.3] - 2026/09/30

- Investigated proxied-traffic latency: fixed a blocking `ipset` call in dns_router.py, and added two redsocks performance patches (proactive Basic auth, `TCP_NODELAY`).

## [1.11.2] - 2026/09/28

- Update documentation and scripts to include versioning information from pyproject.toml

## [1.11.1] - 2026/09/28

- Add release script and configuration for automated releases

## [1.11.0] - 2026/09/28

- Refactor code structure for improved readability and maintainability
- Initial version of the Wi-Fi Proxy Hotspot

