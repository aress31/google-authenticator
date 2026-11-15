package googleauthenticator.session;

import googleauthenticator.otp.TotpGenerator;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Manages authenticator lifecycle and applies one immutable configuration snapshot per request. */
public final class AuthenticatorSession implements AutoCloseable {
    public record ActiveConfiguration(
            TotpGenerator generator, RequestReplacementRule replacementRule) {}

    private final AtomicReference<ActiveConfiguration> activeConfiguration =
            new AtomicReference<>();
    private final AtomicLong updatedRequestCount = new AtomicLong();
    private final AtomicReference<String> lastError = new AtomicReference<>();
    private final Clock clock;
    private boolean closed;

    public AuthenticatorSession() {
        this(Clock.systemUTC());
    }

    public AuthenticatorSession(Clock clock) {
        this.clock = clock;
    }

    public synchronized void start(
            TotpGenerator generator, RequestReplacementRule replacementRule) {
        if (closed) {
            throw new IllegalStateException("The extension has been unloaded.");
        }
        activeConfiguration.set(new ActiveConfiguration(generator, replacementRule));
        lastError.set(null);
    }

    public void stop() {
        activeConfiguration.set(null);
        lastError.set(null);
    }

    @Override
    public synchronized void close() {
        closed = true;
        stop();
    }

    public ActiveConfiguration getActiveConfiguration() {
        return activeConfiguration.get();
    }

    public Instant getCurrentTime() {
        return clock.instant();
    }

    public long getUpdatedRequestCount() {
        return updatedRequestCount.get();
    }

    public String getLastError() {
        return lastError.get();
    }

    public HttpRequestRewriter.RewriteResult rewrite(byte[] requestBytes) {
        ActiveConfiguration configurationSnapshot = activeConfiguration.get();
        if (configurationSnapshot == null) {
            return new HttpRequestRewriter.RewriteResult(requestBytes, 0);
        }
        try {
            var rewriteResult =
                    HttpRequestRewriter.rewrite(
                            requestBytes,
                            configurationSnapshot.replacementRule(),
                            configurationSnapshot.generator().generateCode(getCurrentTime()));
            if (rewriteResult.replacementCount() > 0) {
                updatedRequestCount.incrementAndGet();
                lastError.set(null);
            }
            return rewriteResult;
        } catch (IllegalArgumentException | IllegalStateException e) {
            lastError.set(e.getMessage());
            return new HttpRequestRewriter.RewriteResult(requestBytes, 0);
        }
    }
}
