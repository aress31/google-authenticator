package googleauthenticator.session;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;

import googleauthenticator.otp.TotpGenerator;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/** Manages authenticator lifecycle and applies one immutable configuration snapshot per request. */
@RequiredArgsConstructor
public final class AuthenticatorSession implements AutoCloseable {
    public record ActiveConfiguration(
            TotpGenerator generator, RequestReplacementRule replacementRule) {}

    @Getter private volatile ActiveConfiguration activeConfiguration;
    private final AtomicLong updatedRequestCount = new AtomicLong();
    @Getter private volatile String lastError;
    private final Clock clock;
    private boolean closed;

    public AuthenticatorSession() {
        this(Clock.systemUTC());
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

    public Instant getCurrentTime() {
        return clock.instant();
    }

    public long getUpdatedRequestCount() {
        return updatedRequestCount.get();
    }

    public HttpRequest rewrite(HttpRequest request) {
        ActiveConfiguration configurationSnapshot = activeConfiguration;
        if (configurationSnapshot == null) {
            return request;
        }
        try {
            HttpRequest rewrittenRequest =
                    HttpRequestRewriter.rewrite(
                            request,
                            configurationSnapshot.replacementRule(),
                            configurationSnapshot.generator().generateCode(getCurrentTime()));
            if (rewrittenRequest != request) {
                updatedRequestCount.incrementAndGet();
                lastError = null;
            }
            return rewrittenRequest;
        } catch (MalformedRequestException e) {
            lastError = "Burp could not parse the request; left unchanged.";
            return request;
        } catch (IllegalArgumentException | IllegalStateException e) {
            lastError = e.getMessage();
            return request;
        }
    }
}
