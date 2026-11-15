# Changelog

## 2.0.0

- Modernize the interface with Burp theme support and masked secret entry.
- Add provisioning URI import, SHA-256/SHA-512, 8-digit codes and configurable periods.
- Generate fresh codes for each processed request and preserve leading zeroes.
- Improve literal and regex replacement, including named `otp` capture groups.
- Add a code countdown, clipboard copy, rule testing and request counts.
- Add explicit start, stop and clear-secret controls, with updates paused when settings change.

Requires Burp Suite 2026.7 or later and Java 21 or later.
When upgrading from 1.x, re-enter the configuration and reselect the extension action in existing session rules.
