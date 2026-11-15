package googleauthenticator.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;

class TotpInputParserTest {
    @Test
    void rawSecretUsesSelectedOptions() {
        TotpGenerator generator =
                TotpInputParser.parse("JBSWY3DPEHPK3PXP", TotpGenerator.Algorithm.SHA256, 8, 60);
        assertEquals(TotpGenerator.Algorithm.SHA256, generator.getAlgorithm());
        assertEquals(8, generator.getCodeLength());
        assertEquals(60, generator.getPeriodSeconds());
    }

    @Test
    void importsPercentEncodedUriAndOverridesFormOptions() {
        TotpGenerator generator =
                TotpInputParser.parse(
                        "otpauth://totp/Example%3Aalice?secret=JBSWY3DPEHPK3PXP"
                                + "&issuer=Example&algorithm=SHA512&digits=8&period=60",
                        TotpGenerator.Algorithm.SHA1, 6, 30);
        assertEquals(TotpGenerator.Algorithm.SHA512, generator.getAlgorithm());
        assertEquals(8, generator.getCodeLength());
        assertEquals(60, generator.getPeriodSeconds());
        assertEquals(
                new TotpGenerator("JBSWY3DPEHPK3PXP", TotpGenerator.Algorithm.SHA512, 8, 60)
                        .generateCode(Instant.EPOCH),
                generator.generateCode(Instant.EPOCH));
    }

    @Test
    void uriUsesStandardDefaultsRatherThanPreviousFormValues() {
        TotpGenerator generator =
                TotpInputParser.parse(
                        "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP",
                        TotpGenerator.Algorithm.SHA512,
                        8,
                        60);
        assertEquals(TotpGenerator.Algorithm.SHA1, generator.getAlgorithm());
        assertEquals(6, generator.getCodeLength());
        assertEquals(30, generator.getPeriodSeconds());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=1",
                "otpauth://totp/Test?issuer=Example",
                "otpauth://totp/Test?secret=private!",
                "otpauth://totp/Test?secret=MY&secret=MY",
                "otpauth://totp/Test?secret=MY&algorithm=MD5",
                "otpauth://totp/Test?secret=MY&digits=7",
                "otpauth://totp/Test?secret=MY&period=0",
                "otpauth://totp/Test?secret=%ZZ",
                "otpauth://totp/Test?secret=MY#fragment",
                "otpauth://user@totp/Test?secret=MY",
                "otpauth://totp:42/Test?secret=MY"
            })
    void rejectsMalformedOrUnsupportedUrisWithoutLeakingInput(String input) {
        var error =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> TotpInputParser.parse(input, TotpGenerator.Algorithm.SHA1, 6, 30));
        assertFalse(error.getMessage().contains(input));
        assertNull(error.getCause());
    }
}
