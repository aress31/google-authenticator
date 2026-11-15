package googleauthenticator.session;

import static org.junit.jupiter.api.Assertions.*;

import googleauthenticator.otp.Totp;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class SessionStateTest {
    private static final Totp TOTP = new Totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Totp.Algorithm.SHA1, 6, 30);
    private static final byte[] REQUEST = "POST / HTTP/1.1\r\n\r\n{{TOTP}}".getBytes(StandardCharsets.ISO_8859_1);

    @Test
    void refreshesAtSendTimeWithoutUiTimer() {
        AtomicReference<Instant> time = new AtomicReference<>(Instant.ofEpochSecond(59));
        Clock clock = new Clock() {
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return time.get(); }
        };
        var state = new SessionState(clock);
        assertSame(REQUEST, state.rewrite(REQUEST).request());
        state.start(TOTP, new MatchRule("{{TOTP}}", false, true));
        String first = new String(state.rewrite(REQUEST).request(), StandardCharsets.ISO_8859_1);
        time.set(Instant.ofEpochSecond(60));
        String second = new String(state.rewrite(REQUEST).request(), StandardCharsets.ISO_8859_1);
        assertTrue(first.endsWith(TOTP.codeAt(Instant.ofEpochSecond(59))));
        assertTrue(second.endsWith(TOTP.codeAt(Instant.ofEpochSecond(60))));
        assertNotEquals(first, second);
        assertEquals(2, state.updatedRequests());
        state.stop();
        assertSame(REQUEST, state.rewrite(REQUEST).request());
    }

    @Test
    void concurrentRequestsUseIndependentMacInstances() throws Exception {
        var state = new SessionState(Clock.fixed(Instant.ofEpochSecond(1111111109), ZoneOffset.UTC));
        state.start(TOTP, new MatchRule("{{TOTP}}", false, true));
        try (var executor = Executors.newFixedThreadPool(8)) {
            var tasks = IntStream.range(0, 100).mapToObj(i -> executor.submit(() -> state.rewrite(REQUEST))).toList();
            for (var task : tasks) {
                assertTrue(new String(task.get().request(), StandardCharsets.ISO_8859_1).endsWith("081804"));
            }
        }
        assertEquals(100, state.updatedRequests());
    }

    @Test
    void invalidRequestsRemainUntouchedAndExposeOnlyAnActionableIssue() {
        var state = new SessionState();
        state.start(TOTP, new MatchRule("(?=a)", true, true));
        byte[] request = "POST / HTTP/1.1\r\n\r\na".getBytes(StandardCharsets.ISO_8859_1);
        assertSame(request, state.rewrite(request).request());
        assertEquals(0, state.updatedRequests());
        assertTrue(state.lastIssue().contains("empty"));
        state.start(TOTP, new MatchRule("{{TOTP}}", false, true));
        assertNull(state.lastIssue());
    }

    @Test
    void unloadingPreventsQueuedUiEventsFromReactivatingTheConfiguration() {
        var state = new SessionState();
        state.start(TOTP, new MatchRule("{{TOTP}}", false, true));
        state.close();
        assertNull(state.configuration());
        assertThrows(IllegalStateException.class,
                () -> state.start(TOTP, new MatchRule("{{TOTP}}", false, true)));
        assertSame(REQUEST, state.rewrite(REQUEST).request());
    }
}
