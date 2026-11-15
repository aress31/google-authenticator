package googleauthenticator.session;

import googleauthenticator.otp.TotpGenerator;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/** Manages authenticator lifecycle and applies one immutable configuration snapshot per request. */
public final class AuthenticatorSession implements AutoCloseable {
    public record ActiveConfiguration(
            TotpGenerator generator, RequestReplacementRule replacementRule) {}

    private volatile ActiveConfiguration activeConfiguration;
    private final AtomicLong updatedRequestCount = new AtomicLong();
    private volatile String lastError;
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
        activeConfiguration = new ActiveConfiguration(generator, replacementRule);
        lastError = null;
    }

    public void stop() {
        activeConfiguration = null;
        lastError = null;
    }

    @Override
    public synchronized void close() {
        closed = true;
        stop();
    }

    public ActiveConfiguration getActiveConfiguration() {
        return activeConfiguration;
    }

    public Instant getCurrentTime() {
        return clock.instant();
    }

    public long getUpdatedRequestCount() {
        return updatedRequestCount.get();
    }

    public String getLastError() {
        return lastError;
    }

    public HttpRequestRewriter.RewriteResult rewrite(byte[] requestBytes) {
        ActiveConfiguration configurationSnapshot = activeConfiguration;
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
                lastError = null;
            }
            return rewriteResult;
        } catch (IllegalArgumentException | IllegalStateException e) {
            lastError = e.getMessage();
            return new HttpRequestRewriter.RewriteResult(requestBytes, 0);
        }
    }
}
