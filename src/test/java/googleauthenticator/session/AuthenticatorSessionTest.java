package googleauthenticator.session;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import googleauthenticator.otp.TotpGenerator;

import org.junit.jupiter.api.Test;

class AuthenticatorSessionTest {
    private static final TotpGenerator GENERATOR =
            new TotpGenerator(
                    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", TotpGenerator.Algorithm.SHA1, 6, 30);
    private static final RequestReplacementRule RULE =
            new RequestReplacementRule("{{TOTP}}", false, true);

    @Test
    void startingAndStoppingControlsTheActiveConfiguration() {
        try (var session = new AuthenticatorSession()) {
            session.start(GENERATOR, RULE);
            assertSame(GENERATOR, session.getActiveConfiguration().generator());
            assertSame(RULE, session.getActiveConfiguration().replacementRule());
            session.stop();
            assertNull(session.getActiveConfiguration());
        }
    }

    @Test
    void unloadingClearsConfigurationAndPreventsRestart() {
        var session = new AuthenticatorSession();
        session.start(GENERATOR, RULE);
        session.close();
        assertNull(session.getActiveConfiguration());
        assertThrows(IllegalStateException.class, () -> session.start(GENERATOR, RULE));
    }
}
