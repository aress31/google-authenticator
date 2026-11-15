package googleauthenticator.otp;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 6238 TOTP, using only the JDK's cryptographic providers. */
public final class Totp {
    public enum Algorithm {
        SHA1("HmacSHA1"), SHA256("HmacSHA256"), SHA512("HmacSHA512");

        private final String macName;

        Algorithm(String macName) {
            this.macName = macName;
        }
    }

    private final byte[] secret;
    private final Algorithm algorithm;
    private final int digits;
    private final int period;

    public Totp(String base32, Algorithm algorithm, int digits, int period) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Select a TOTP algorithm.");
        }
        if (digits != 6 && digits != 8) {
            throw new IllegalArgumentException("TOTP codes must contain 6 or 8 digits.");
        }
        if (period < 1 || period > 300) {
            throw new IllegalArgumentException("The period must be between 1 and 300 seconds.");
        }
        this.secret = decodeBase32(base32);
        this.algorithm = algorithm;
        this.digits = digits;
        this.period = period;
    }

    public String codeAt(Instant instant) {
        if (instant.getEpochSecond() < 0) {
            throw new IllegalArgumentException("The system clock must be after the Unix epoch.");
        }
        long counter = instant.getEpochSecond() / period;
        try {
            // Mac is deliberately per-call: requests can arrive concurrently.
            Mac mac = Mac.getInstance(algorithm.macName);
            mac.init(new SecretKeySpec(secret, algorithm.macName));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(counter).array());
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            int modulus = digits == 6 ? 1_000_000 : 100_000_000;
            return String.format(Locale.ROOT, "%0" + digits + "d", binary % modulus);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("The Java runtime does not support this TOTP algorithm.");
        }
    }

    public int secondsRemaining(Instant instant) {
        return period - (int) Math.floorMod(instant.getEpochSecond(), (long) period);
    }

    public Algorithm algorithm() { return algorithm; }
    public int digits() { return digits; }
    public int period() { return period; }

    private static byte[] decodeBase32(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Enter a Base32 shared secret or an otpauth://totp URI.");
        }
        String encoded = input.replaceAll("\\s", "").toUpperCase(Locale.ROOT);
        int paddingStart = encoded.indexOf('=');
        String data = paddingStart < 0 ? encoded : encoded.substring(0, paddingStart);
        int remainder = data.length() % 8;
        if (data.isEmpty() || remainder == 1 || remainder == 3 || remainder == 6) {
            throw new IllegalArgumentException("The shared secret is not valid Base32.");
        }
        if (paddingStart >= 0 && (remainder == 0 || encoded.length() - paddingStart != 8 - remainder
                || !encoded.substring(paddingStart).matches("=+"))) {
            throw new IllegalArgumentException("The Base32 padding is invalid.");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : data.toCharArray()) {
            int value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);
            if (value < 0) {
                throw new IllegalArgumentException("Base32 secrets use only A-Z and 2-7 (spaces are allowed).");
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                output.write((buffer >> bits) & 0xff);
            }
        }
        if ((buffer & ((1 << bits) - 1)) != 0) {
            throw new IllegalArgumentException("The Base32 secret has invalid trailing bits.");
        }
        return output.toByteArray();
    }

    @Override
    public String toString() {
        return "Totp[secret=REDACTED, algorithm=" + algorithm + ", digits=" + digits + ", period=" + period + "]";
    }
}
