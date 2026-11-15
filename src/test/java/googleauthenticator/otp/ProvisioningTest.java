package googleauthenticator.otp;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ProvisioningTest {
    @Test
    void rawSecretUsesSelectedOptions() {
        Totp totp = Provisioning.parse("JBSWY3DPEHPK3PXP", Totp.Algorithm.SHA256, 8, 60);
        assertEquals(Totp.Algorithm.SHA256, totp.algorithm());
        assertEquals(8, totp.digits());
        assertEquals(60, totp.period());
    }

    @Test
    void importsPercentEncodedUriAndOverridesFormOptions() {
        Totp totp = Provisioning.parse("otpauth://totp/Example%3Aalice?secret=JBSWY3DPEHPK3PXP"
                + "&issuer=Example&algorithm=SHA512&digits=8&period=60", Totp.Algorithm.SHA1, 6, 30);
        assertEquals(Totp.Algorithm.SHA512, totp.algorithm());
        assertEquals(8, totp.digits());
        assertEquals(60, totp.period());
        assertEquals(new Totp("JBSWY3DPEHPK3PXP", Totp.Algorithm.SHA512, 8, 60).codeAt(Instant.EPOCH),
                totp.codeAt(Instant.EPOCH));
    }

    @Test
    void uriUsesStandardDefaultsRatherThanPreviousFormValues() {
        Totp totp = Provisioning.parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP", Totp.Algorithm.SHA512, 8, 60);
        assertEquals(Totp.Algorithm.SHA1, totp.algorithm());
        assertEquals(6, totp.digits());
        assertEquals(30, totp.period());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=1",
        "otpauth://totp/Test?issuer=Example", "otpauth://totp/Test?secret=private!",
        "otpauth://totp/Test?secret=MY&secret=MY", "otpauth://totp/Test?secret=MY&algorithm=MD5",
        "otpauth://totp/Test?secret=MY&digits=7", "otpauth://totp/Test?secret=MY&period=0",
        "otpauth://totp/Test?secret=%ZZ", "otpauth://totp/Test?secret=MY#fragment",
        "otpauth://user@totp/Test?secret=MY", "otpauth://totp:42/Test?secret=MY"
    })
    void rejectsMalformedOrUnsupportedUrisWithoutLeakingInput(String input) {
        var error = assertThrows(IllegalArgumentException.class,
                () -> Provisioning.parse(input, Totp.Algorithm.SHA1, 6, 30));
        assertFalse(error.getMessage().contains(input));
        assertNull(error.getCause());
    }
}
