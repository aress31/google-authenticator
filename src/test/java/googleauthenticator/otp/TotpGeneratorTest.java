package googleauthenticator.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.Locale;
import java.util.stream.Stream;

class TotpGeneratorTest {
    private static final String SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String SHA256_SECRET =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    private static final String SHA512_SECRET =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                    + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    static Stream<Arguments> rfc6238Vectors() {
        long[] timestamps = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000L};
        String[][] expectedCodes = {
            {"94287082", "46119246", "90693936"},
            {"07081804", "68084774", "25091201"},
            {"14050471", "67062674", "99943326"},
            {"89005924", "91819424", "93441116"},
            {"69279037", "90698825", "38618901"},
            {"65353130", "77737706", "47863826"}
        };
        Stream.Builder<Arguments> vectors = Stream.builder();
        for (int i = 0; i < timestamps.length; i++) {
            vectors.add(
                    Arguments.of(
                            SHA1_SECRET,
                            TotpGenerator.Algorithm.SHA1,
                            timestamps[i],
                            expectedCodes[i][0]));
            vectors.add(
                    Arguments.of(
                            SHA256_SECRET,
                            TotpGenerator.Algorithm.SHA256,
                            timestamps[i],
                            expectedCodes[i][1]));
            vectors.add(
                    Arguments.of(
                            SHA512_SECRET,
                            TotpGenerator.Algorithm.SHA512,
                            timestamps[i],
                            expectedCodes[i][2]));
        }
        return vectors.build();
    }

    @ParameterizedTest
    @MethodSource("rfc6238Vectors")
    void matchesAllRfc6238Vectors(
            String base32Secret,
            TotpGenerator.Algorithm algorithm,
            long epochSeconds,
            String expectedCode) {
        assertEquals(
                expectedCode,
                new TotpGenerator(base32Secret, algorithm, 8, 30)
                        .generateCode(Instant.ofEpochSecond(epochSeconds)));
    }

    @Test
    void preservesLeadingZerosAndAsciiDigitsRegardlessOfLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar"));
            assertEquals(
                    "081804",
                    new TotpGenerator(SHA1_SECRET, TotpGenerator.Algorithm.SHA1, 6, 30)
                            .generateCode(Instant.ofEpochSecond(1111111109)));
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    void acceptsLowercaseWhitespaceAndCorrectPadding() {
        var expectedCode =
                new TotpGenerator("MZXW6===", TotpGenerator.Algorithm.SHA1, 6, 30)
                        .generateCode(Instant.EPOCH);
        assertEquals(
                expectedCode,
                new TotpGenerator(" mz xw6 \n", TotpGenerator.Algorithm.SHA1, 6, 30)
                        .generateCode(Instant.EPOCH));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "",
                " ",
                "A",
                "ABC",
                "ABCDEF",
                "MZ",
                "MZXW6=",
                "MZXW6======",
                "MZXW6==A",
                "MZXW6YTB========",
                "secret!",
                "42TCJUDP94W27YR3"
            })
    void rejectsMalformedBase32(String base32Secret) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new TotpGenerator(base32Secret, TotpGenerator.Algorithm.SHA1, 6, 30));
    }

    @Test
    void validatesConfigurationAndClock() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new TotpGenerator(SHA1_SECRET, TotpGenerator.Algorithm.SHA1, 7, 30));
        assertThrows(
                IllegalArgumentException.class,
                () -> new TotpGenerator(SHA1_SECRET, TotpGenerator.Algorithm.SHA1, 6, 0));
        assertThrows(
                IllegalArgumentException.class,
                () -> new TotpGenerator(SHA1_SECRET, TotpGenerator.Algorithm.SHA1, 6, 301));
        var generator = new TotpGenerator(SHA1_SECRET, TotpGenerator.Algorithm.SHA1, 6, 30);
        assertThrows(
                IllegalArgumentException.class,
                () -> generator.generateCode(Instant.ofEpochSecond(-1)));
        assertEquals(1, generator.getSecondsRemaining(Instant.ofEpochSecond(59)));
        assertEquals(30, generator.getSecondsRemaining(Instant.ofEpochSecond(60)));
        assertEquals(
                generator.generateCode(Instant.ofEpochSecond(30)),
                generator.generateCode(Instant.ofEpochSecond(59)));
        assertNotEquals(
                generator.generateCode(Instant.ofEpochSecond(59)),
                generator.generateCode(Instant.ofEpochSecond(60)));
        assertFalse(generator.toString().contains(SHA1_SECRET));
    }
}
