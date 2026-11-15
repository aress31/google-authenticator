package googleauthenticator.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import googleauthenticator.otp.TotpGenerator;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

class AuthenticatorSessionTest {
    private static final TotpGenerator TOTP_GENERATOR =
            new TotpGenerator(
                    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", TotpGenerator.Algorithm.SHA1, 6, 30);
    private static final byte[] REQUEST_BYTES =
            "POST / HTTP/1.1\r\n\r\n{{TOTP}}".getBytes(StandardCharsets.ISO_8859_1);

    @Test
    void refreshesAtSendTimeWithoutUiTimer() {
        AtomicReference<Instant> currentTime = new AtomicReference<>(Instant.ofEpochSecond(59));
        Clock clock =
                new Clock() {
                    @Override
                    public ZoneId getZone() {
                        return ZoneOffset.UTC;
                    }

                    @Override
                    public Clock withZone(ZoneId zone) {
                        return this;
                    }

                    @Override
                    public Instant instant() {
                        return currentTime.get();
                    }
                };
        var session = new AuthenticatorSession(clock);
        assertSame(REQUEST_BYTES, session.rewrite(REQUEST_BYTES).requestBytes());
        session.start(TOTP_GENERATOR, new RequestReplacementRule("{{TOTP}}", false, true));
        String firstRequest =
                new String(
                        session.rewrite(REQUEST_BYTES).requestBytes(), StandardCharsets.ISO_8859_1);
        currentTime.set(Instant.ofEpochSecond(60));
        String secondRequest =
                new String(
                        session.rewrite(REQUEST_BYTES).requestBytes(), StandardCharsets.ISO_8859_1);
        assertTrue(firstRequest.endsWith(TOTP_GENERATOR.generateCode(Instant.ofEpochSecond(59))));
        assertTrue(secondRequest.endsWith(TOTP_GENERATOR.generateCode(Instant.ofEpochSecond(60))));
        assertNotEquals(firstRequest, secondRequest);
        assertEquals(2, session.getUpdatedRequestCount());
        session.stop();
        assertSame(REQUEST_BYTES, session.rewrite(REQUEST_BYTES).requestBytes());
    }

    @Test
    void concurrentRequestsUseIndependentMacInstances() throws Exception {
        var session =
                new AuthenticatorSession(
                        Clock.fixed(Instant.ofEpochSecond(1111111109), ZoneOffset.UTC));
        session.start(TOTP_GENERATOR, new RequestReplacementRule("{{TOTP}}", false, true));
        try (var executor = Executors.newFixedThreadPool(8)) {
            var tasks =
                    IntStream.range(0, 100)
                            .mapToObj(i -> executor.submit(() -> session.rewrite(REQUEST_BYTES)))
                            .toList();
            for (var task : tasks) {
                assertTrue(
                        new String(task.get().requestBytes(), StandardCharsets.ISO_8859_1)
                                .endsWith("081804"));
            }
        }
        assertEquals(100, session.getUpdatedRequestCount());
    }

    @Test
    void invalidRequestsRemainUntouchedAndExposeOnlyAnActionableIssue() {
        var session = new AuthenticatorSession();
        session.start(TOTP_GENERATOR, new RequestReplacementRule("(?=a)", true, true));
        byte[] requestBytes = "POST / HTTP/1.1\r\n\r\na".getBytes(StandardCharsets.ISO_8859_1);
        assertSame(requestBytes, session.rewrite(requestBytes).requestBytes());
        assertEquals(0, session.getUpdatedRequestCount());
        assertTrue(session.getLastError().contains("empty"));
        session.start(TOTP_GENERATOR, new RequestReplacementRule("{{TOTP}}", false, true));
        assertNull(session.getLastError());
    }

    @Test
    void unloadingPreventsQueuedUiEventsFromReactivatingTheConfiguration() {
        var session = new AuthenticatorSession();
        session.start(TOTP_GENERATOR, new RequestReplacementRule("{{TOTP}}", false, true));
        session.close();
        assertNull(session.getActiveConfiguration());
        assertThrows(
                IllegalStateException.class,
                () ->
                        session.start(
                                TOTP_GENERATOR,
                                new RequestReplacementRule("{{TOTP}}", false, true)));
        assertSame(REQUEST_BYTES, session.rewrite(REQUEST_BYTES).requestBytes());
    }
}
