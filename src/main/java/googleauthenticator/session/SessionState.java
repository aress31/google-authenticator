package googleauthenticator.session;

import googleauthenticator.otp.Totp;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** One immutable configuration snapshot per request; never relies on the Swing refresh timer. */
public final class SessionState implements AutoCloseable {
    public record Configuration(Totp totp, MatchRule rule) { }

    private final AtomicReference<Configuration> active = new AtomicReference<>();
    private final AtomicLong updated = new AtomicLong();
    private final AtomicReference<String> lastIssue = new AtomicReference<>();
    private final Clock clock;
    private boolean closed;

    public SessionState() { this(Clock.systemUTC()); }
    public SessionState(Clock clock) { this.clock = clock; }

    public synchronized void start(Totp totp, MatchRule rule) {
        if (closed) {
            throw new IllegalStateException("The extension has been unloaded.");
        }
        active.set(new Configuration(totp, rule));
        lastIssue.set(null);
    }

    public void stop() {
        active.set(null);
        lastIssue.set(null);
    }

    @Override
    public synchronized void close() {
        closed = true;
        stop();
    }
    public Configuration configuration() { return active.get(); }
    public Instant now() { return clock.instant(); }
    public long updatedRequests() { return updated.get(); }
    public String lastIssue() { return lastIssue.get(); }

    public RequestRewriter.Result rewrite(byte[] request) {
        Configuration snapshot = active.get();
        if (snapshot == null) {
            return new RequestRewriter.Result(request, 0);
        }
        try {
            var result = RequestRewriter.rewrite(request, snapshot.rule(), snapshot.totp().codeAt(now()));
            if (result.matches() > 0) {
                updated.incrementAndGet();
                lastIssue.set(null);
            }
            return result;
        } catch (IllegalArgumentException | IllegalStateException e) {
            lastIssue.set(e.getMessage());
            return new RequestRewriter.Result(request, 0);
        }
    }
}
