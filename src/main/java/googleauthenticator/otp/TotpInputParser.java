package googleauthenticator.otp;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Parses a manually entered secret or a standard authenticator provisioning URI. */
public final class TotpInputParser {
    private TotpInputParser() {}

    public static TotpGenerator parse(
            String input, TotpGenerator.Algorithm algorithm, int codeLength, int periodSeconds) {
        String normalizedInput = input == null ? "" : input.strip();
        if (!normalizedInput.regionMatches(true, 0, "otpauth:", 0, 8)) {
            return new TotpGenerator(normalizedInput, algorithm, codeLength, periodSeconds);
        }
        try {
            URI provisioningUri = URI.create(normalizedInput);
            if (!"otpauth".equalsIgnoreCase(provisioningUri.getScheme())
                    || !"totp".equalsIgnoreCase(provisioningUri.getHost())
                    || provisioningUri.getRawQuery() == null
                    || provisioningUri.getFragment() != null
                    || provisioningUri.getUserInfo() != null
                    || provisioningUri.getPort() != -1) {
                throw invalidProvisioningUri();
            }
            Map<String, String> parameters = new HashMap<>();
            for (String queryParameter : provisioningUri.getRawQuery().split("&")) {
                String[] parameterParts = queryParameter.split("=", 2);
                String parameterName = URLDecoder.decode(parameterParts[0], StandardCharsets.UTF_8);
                String parameterValue =
                        parameterParts.length == 2
                                ? URLDecoder.decode(parameterParts[1], StandardCharsets.UTF_8)
                                : "";
                if (parameters.putIfAbsent(parameterName, parameterValue) != null) {
                    throw invalidProvisioningUri();
                }
            }
            // URI defaults are part of the provisioning format, not the current form state.
            return new TotpGenerator(
                    parameters.get("secret"),
                    TotpGenerator.Algorithm.valueOf(
                            parameters.getOrDefault("algorithm", "SHA1").toUpperCase(Locale.ROOT)),
                    Integer.parseInt(parameters.getOrDefault("digits", "6")),
                    Integer.parseInt(parameters.getOrDefault("period", "30")));
        } catch (IllegalArgumentException e) {
            // URI exceptions can include the whole secret. Never expose their messages.
            throw invalidProvisioningUri();
        }
    }

    private static IllegalArgumentException invalidProvisioningUri() {
        return new IllegalArgumentException(
                "Invalid TOTP URI. Use otpauth://totp with a Base32 secret, "
                        + "SHA1/SHA256/SHA512, 6/8 digits and a period of 1-300 seconds. HOTP is not supported.");
    }
}
