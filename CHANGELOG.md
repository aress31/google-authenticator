# Changelog

## 2.0.0

- Migrate to Java 21 and Burp's Montoya extension API (2026.7).
- Replace the legacy interface with theme-aware controls, masked secrets, expiry progress,
  clipboard copy, local rule previews and a request update counter. Stack the layout in narrow tabs.
- Add TOTP provisioning URI import, SHA-256/SHA-512, 8-digit codes and configurable periods.
- Generate codes at request-processing time and preserve leading zeroes.
- Fix literal matching, validate regexes before activation, and support named `otp` capture groups.
- Default to a precise body placeholder; preserve binary bytes and repair body lengths after replacement.
  Skip encoded body changes and invalid runtime matches without modifying the request.
- Pause on configuration edits, provide explicit stop/clear controls, and clean up on extension unload.
- Remove runtime dependencies and secret-bearing debug output.
- Add a checksum-pinned Gradle wrapper, dependency verification, reproducible JAR packaging,
  regression tests and Linux/Windows CI.
- Use GradleUp Shadow for the loadable extension JAR, a Java 21 toolchain,
  build/configuration caches and standard Gradle lifecycle tasks.
- Update installation, session rule setup, migration and privacy documentation.
- Standardise class and method names, explicit time units, result fields and Swing component names;
  align unit test classes with their subjects and document the naming conventions.

This release requires Burp Suite 2026.7 or newer and Java 21 or newer. Reconfigure or reselect
the extension action in existing session handling rules when upgrading from 1.x.
