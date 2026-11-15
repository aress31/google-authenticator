# Google Authenticator for Burp Suite

Generate fresh time-based one-time passwords (TOTP) and apply them to requests through Burp session handling rules.
Supports Google Authenticator and other RFC 6238-compatible authenticators.

**Requires Burp Suite 2026.7 or later and Java 21 or later.**

![Google Authenticator interface](.github/assets/configuration-modern.png)

## Features

- Base32 shared secrets and `otpauth://totp` provisioning URIs.
- SHA-1, SHA-256 and SHA-512, with 6 or 8 digits and configurable periods.
- Literal or regular-expression replacement in request bodies, headers and URLs.
- Masked secret entry, code countdown, clipboard copy and local rule testing.
- Secrets held in memory only.

## Build and install

With JDK 21 or later installed, run:

```sh
./gradlew build
```

On Windows, use `.\gradlew.bat build`.

Load `build/libs/google-authenticator-all.jar` in Burp under **Extensions > Installed > Add**, selecting **Java**.

## Usage

1. Open the **Google Authenticator** tab and enter a shared secret or provisioning URI.
2. Place `{{TOTP}}` in the request body, or configure a replacement expression.
3. Click **Apply & start**.
4. Under **Settings > Sessions > Session handling rules**, add an **Invoke a Burp extension** action
   and select Google Authenticator. Scope the rule to the intended requests and tools.

For headers or URL values, uncheck **Request body only**. In regular-expression mode, a named `otp` capture
group limits replacement to that value. Use **Test rule...** to check a match before enabling it.

Editing the configuration pauses updates. **Stop** pauses request changes; **Clear secret** also empties the secret field.
Keep your system clock synchronized.

## Notes

The extension does not save shared secrets or write secrets and codes to its logs.
Copied codes can remain on the clipboard, and modified requests can remain in Burp's history or project files.
Encoded or transfer-encoded request bodies are left unchanged.

Run automated tests with `./gradlew test`. Request rewriting should also be checked in Burp.
Format Java sources with `./gradlew format` (`.\gradlew.bat format` on Windows).

## Issues

Use the [issue forms](https://github.com/aress31/google-authenticator/issues/new/choose) to report bugs or request features.
Use dummy data in reports and screenshots.

## License

Copyright (C) 2018-2026 Alexandre Teyar. Licensed under [Apache License 2.0](LICENSE).

MigLayout is distributed under its [BSD license](src/main/resources/META-INF/LICENSE-MigLayout.txt).
