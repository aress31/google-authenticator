package googleauthenticator.otp;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class TotpTest {
    private static final String SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String SHA256_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    private static final String SHA512_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    static Stream<Arguments> rfc6238Vectors() {
        long[] times = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000L};
        String[][] codes = {
            {"94287082", "46119246", "90693936"},
            {"07081804", "68084774", "25091201"},
            {"14050471", "67062674", "99943326"},
            {"89005924", "91819424", "93441116"},
            {"69279037", "90698825", "38618901"},
            {"65353130", "77737706", "47863826"}
        };
        Stream.Builder<Arguments> vectors = Stream.builder();
        for (int i = 0; i < times.length; i++) {
            vectors.add(Arguments.of(SHA1_SECRET, Totp.Algorithm.SHA1, times[i], codes[i][0]));
            vectors.add(Arguments.of(SHA256_SECRET, Totp.Algorithm.SHA256, times[i], codes[i][1]));
            vectors.add(Arguments.of(SHA512_SECRET, Totp.Algorithm.SHA512, times[i], codes[i][2]));
        }
        return vectors.build();
    }

    @ParameterizedTest
    @MethodSource("rfc6238Vectors")
    void matchesAllRfc6238Vectors(String secret, Totp.Algorithm algorithm, long time, String expected) {
        assertEquals(expected, new Totp(secret, algorithm, 8, 30).codeAt(Instant.ofEpochSecond(time)));
    }

    @Test
    void preservesLeadingZerosAndAsciiDigitsRegardlessOfLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar"));
            assertEquals("081804", new Totp(SHA1_SECRET, Totp.Algorithm.SHA1, 6, 30)
                    .codeAt(Instant.ofEpochSecond(1111111109)));
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    void acceptsLowercaseWhitespaceAndCorrectPadding() {
        var expected = new Totp("MZXW6===", Totp.Algorithm.SHA1, 6, 30).codeAt(Instant.EPOCH);
        assertEquals(expected, new Totp(" mz xw6 \n", Totp.Algorithm.SHA1, 6, 30).codeAt(Instant.EPOCH));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "A", "ABC", "ABCDEF", "MZ", "MZXW6=", "MZXW6======", "MZXW6==A", "MZXW6YTB========", "secret!", "42TCJUDP94W27YR3"})
    void rejectsMalformedBase32(String secret) {
        assertThrows(IllegalArgumentException.class, () -> new Totp(secret, Totp.Algorithm.SHA1, 6, 30));
    }

    @Test
    void validatesConfigurationAndClock() {
        assertThrows(IllegalArgumentException.class, () -> new Totp(SHA1_SECRET, Totp.Algorithm.SHA1, 7, 30));
        assertThrows(IllegalArgumentException.class, () -> new Totp(SHA1_SECRET, Totp.Algorithm.SHA1, 6, 0));
        assertThrows(IllegalArgumentException.class, () -> new Totp(SHA1_SECRET, Totp.Algorithm.SHA1, 6, 301));
        var totp = new Totp(SHA1_SECRET, Totp.Algorithm.SHA1, 6, 30);
        assertThrows(IllegalArgumentException.class, () -> totp.codeAt(Instant.ofEpochSecond(-1)));
        assertEquals(1, totp.secondsRemaining(Instant.ofEpochSecond(59)));
        assertEquals(30, totp.secondsRemaining(Instant.ofEpochSecond(60)));
        assertEquals(totp.codeAt(Instant.ofEpochSecond(30)), totp.codeAt(Instant.ofEpochSecond(59)));
        assertNotEquals(totp.codeAt(Instant.ofEpochSecond(59)), totp.codeAt(Instant.ofEpochSecond(60)));
        assertFalse(totp.toString().contains(SHA1_SECRET));
    }
}
