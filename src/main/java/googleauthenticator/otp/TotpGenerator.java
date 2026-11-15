package googleauthenticator.otp;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Generates RFC 6238 TOTP codes using the JDK's cryptographic providers. */
public final class TotpGenerator {
    public enum Algorithm {
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA512("HmacSHA512");

        private final String hmacAlgorithmName;

        Algorithm(String hmacAlgorithmName) {
            this.hmacAlgorithmName = hmacAlgorithmName;
        }
    }

    private final byte[] secretBytes;
    private final Algorithm algorithm;
    private final int codeLength;
    private final int periodSeconds;

    public TotpGenerator(
            String base32Secret, Algorithm algorithm, int codeLength, int periodSeconds) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Select a TOTP algorithm.");
        }
        if (codeLength != 6 && codeLength != 8) {
            throw new IllegalArgumentException("TOTP codes must contain 6 or 8 digits.");
        }
        if (periodSeconds < 1 || periodSeconds > 300) {
            throw new IllegalArgumentException("The period must be between 1 and 300 seconds.");
        }
        this.secretBytes = decodeBase32(base32Secret);
        this.algorithm = algorithm;
        this.codeLength = codeLength;
        this.periodSeconds = periodSeconds;
    }

    public String generateCode(Instant instant) {
        if (instant.getEpochSecond() < 0) {
            throw new IllegalArgumentException("The system clock must be after the Unix epoch.");
        }
        long counter = instant.getEpochSecond() / periodSeconds;
        try {
            // Mac is deliberately per-call: requests can arrive concurrently.
            Mac mac = Mac.getInstance(algorithm.hmacAlgorithmName);
            mac.init(new SecretKeySpec(secretBytes, algorithm.hmacAlgorithmName));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(counter).array());
            int offset = hash[hash.length - 1] & 0x0f;
            int truncatedHash =
                    ((hash[offset] & 0x7f) << 24)
                            | ((hash[offset + 1] & 0xff) << 16)
                            | ((hash[offset + 2] & 0xff) << 8)
                            | (hash[offset + 3] & 0xff);
            int modulus = codeLength == 6 ? 1_000_000 : 100_000_000;
            return String.format(Locale.ROOT, "%0" + codeLength + "d", truncatedHash % modulus);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "The Java runtime does not support this TOTP algorithm.");
        }
    }

    public int getSecondsRemaining(Instant instant) {
        return periodSeconds - (int) Math.floorMod(instant.getEpochSecond(), (long) periodSeconds);
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public int getCodeLength() {
        return codeLength;
    }

    public int getPeriodSeconds() {
        return periodSeconds;
    }

    private static byte[] decodeBase32(String input) {
        if (input == null) {
            throw new IllegalArgumentException(
                    "Enter a Base32 shared secret or an otpauth://totp URI.");
        }
        String normalizedSecret = input.replaceAll("\\s", "").toUpperCase(Locale.ROOT);
        int paddingStart = normalizedSecret.indexOf('=');
        String base32Data =
                paddingStart < 0 ? normalizedSecret : normalizedSecret.substring(0, paddingStart);
        int lengthRemainder = base32Data.length() % 8;
        if (base32Data.isEmpty()
                || lengthRemainder == 1
                || lengthRemainder == 3
                || lengthRemainder == 6) {
            throw new IllegalArgumentException("The shared secret is not valid Base32.");
        }
        if (paddingStart >= 0
                && (lengthRemainder == 0
                        || normalizedSecret.length() - paddingStart != 8 - lengthRemainder
                        || !normalizedSecret.substring(paddingStart).matches("=+"))) {
            throw new IllegalArgumentException("The Base32 padding is invalid.");
        }
        ByteArrayOutputStream decodedSecret = new ByteArrayOutputStream();
        int bitBuffer = 0;
        int bufferedBits = 0;
        for (char character : base32Data.toCharArray()) {
            int decodedValue = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(character);
            if (decodedValue < 0) {
                throw new IllegalArgumentException(
                        "Base32 secrets use only A-Z and 2-7 (spaces are allowed).");
            }
            bitBuffer = (bitBuffer << 5) | decodedValue;
            bufferedBits += 5;
            if (bufferedBits >= 8) {
                bufferedBits -= 8;
                decodedSecret.write((bitBuffer >> bufferedBits) & 0xff);
            }
        }
        if ((bitBuffer & ((1 << bufferedBits) - 1)) != 0) {
            throw new IllegalArgumentException("The Base32 secret has invalid trailing bits.");
        }
        return decodedSecret.toByteArray();
    }

    @Override
    public String toString() {
        return "TotpGenerator[secret=REDACTED, algorithm="
                + algorithm
                + ", codeLength="
                + codeLength
                + ", periodSeconds="
                + periodSeconds
                + "]";
    }
}
