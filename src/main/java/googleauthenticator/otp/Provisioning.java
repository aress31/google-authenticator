package googleauthenticator.otp;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Parses a manually entered secret or a standard authenticator provisioning URI. */
public final class Provisioning {
    private Provisioning() { }

    public static Totp parse(String input, Totp.Algorithm algorithm, int digits, int period) {
        String value = input == null ? "" : input.strip();
        if (!value.regionMatches(true, 0, "otpauth:", 0, 8)) {
            return new Totp(value, algorithm, digits, period);
        }
        try {
            URI uri = new URI(value);
            if (!"otpauth".equalsIgnoreCase(uri.getScheme()) || !"totp".equalsIgnoreCase(uri.getHost())
                    || uri.getRawQuery() == null || uri.getFragment() != null || uri.getUserInfo() != null
                    || uri.getPort() != -1) {
                throw invalidUri();
            }
            Map<String, String> parameters = new HashMap<>();
            for (String pair : uri.getRawQuery().split("&")) {
                String[] parts = pair.split("=", 2);
                String name = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                String parameter = parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
                if (parameters.putIfAbsent(name, parameter) != null) {
                    throw invalidUri();
                }
            }
            // URI defaults are part of the provisioning format, not the current form state.
            return new Totp(parameters.get("secret"),
                    Totp.Algorithm.valueOf(parameters.getOrDefault("algorithm", "SHA1").toUpperCase(Locale.ROOT)),
                    Integer.parseInt(parameters.getOrDefault("digits", "6")),
                    Integer.parseInt(parameters.getOrDefault("period", "30")));
        } catch (URISyntaxException | IllegalArgumentException e) {
            // URI exceptions can include the whole secret. Never expose their messages.
            throw invalidUri();
        }
    }

    private static IllegalArgumentException invalidUri() {
        return new IllegalArgumentException("Invalid TOTP URI. Use otpauth://totp with a Base32 secret, "
                + "SHA1/SHA256/SHA512, 6/8 digits and a period of 1-300 seconds. HOTP is not supported.");
    }
}
