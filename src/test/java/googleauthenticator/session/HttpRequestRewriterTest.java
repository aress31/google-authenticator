package googleauthenticator.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class HttpRequestRewriterTest {
    private static byte[] toRequestBytes(String value) { return value.getBytes(StandardCharsets.ISO_8859_1); }
    private static String toRequestText(byte[] value) { return new String(value, StandardCharsets.ISO_8859_1); }

    @Test
    void updatesBodyAndRepairsAllContentLengthsWhilePreservingBinaryBytes() {
        String requestText = "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10\r\ncontent-length: 10\r\n"
                + "X-Keep: {{TOTP}}\r\n\r\n\u00ff\u0000{{TOTP}}";
        var result = HttpRequestRewriter.rewrite(toRequestBytes(requestText), new RequestReplacementRule("{{TOTP}}", false, true), "081804");
        assertEquals("POST / HTTP/1.1\r\nHost: example.test\r\nX-Keep: {{TOTP}}\r\nContent-Length: 8\r\n\r\n\u00ff\u0000081804",
                toRequestText(result.requestBytes()));
        assertEquals(1, result.replacementCount());
    }

    @Test
    void noMatchOrSameCodeLeavesBytesUntouched() {
        byte[] requestBytes = toRequestBytes("GET / HTTP/1.1\r\nHost: test\r\n\r\n");
        var result = HttpRequestRewriter.rewrite(requestBytes, new RequestReplacementRule("{{TOTP}}", false, true), "123456");
        assertSame(requestBytes, result.requestBytes());
        assertEquals(0, result.replacementCount());
        assertEquals(0, HttpRequestRewriter.rewrite(toRequestBytes("POST / HTTP/1.1\r\n\r\n123456"),
                new RequestReplacementRule("123456", false, true), "123456").replacementCount());
    }

    @Test
    void wholeRequestModeCanReplaceHeaderAndQueryValues() {
        var result = HttpRequestRewriter.rewrite(toRequestBytes("GET /?otp={{TOTP}} HTTP/1.1\r\nX-OTP: {{TOTP}}\r\n\r\n"),
                new RequestReplacementRule("{{TOTP}}", false, false), "123456");
        assertEquals("GET /?otp=123456 HTTP/1.1\r\nX-OTP: 123456\r\n\r\n", toRequestText(result.requestBytes()));
        assertEquals(2, result.replacementCount());
    }

    @Test
    void wholeRequestModeAlsoRepairsBodyLength() {
        var result = HttpRequestRewriter.rewrite(toRequestBytes("POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\n{{TOTP}}"),
                new RequestReplacementRule("{{TOTP}}", false, false), "123456");
        assertTrue(toRequestText(result.requestBytes()).contains("Content-Length: 6\r\n\r\n123456"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Transfer-Encoding: chunked", "Transfer-Encoding: gzip", "Content-Encoding: gzip", "Content-Encoding: br"})
    void rejectsEncodedBodyChanges(String encoding) {
        assertThrows(IllegalArgumentException.class, () -> HttpRequestRewriter.rewrite(
                toRequestBytes("POST / HTTP/1.1\r\n" + encoding + "\r\n\r\n{{TOTP}}"),
                new RequestReplacementRule("{{TOTP}}", false, true), "123456"));
    }

    @Test
    void permitsIdentityEncodingAndHeaderOnlyChangesOnEncodedMessages() {
        assertEquals(1, HttpRequestRewriter.rewrite(toRequestBytes("POST / HTTP/1.1\r\nContent-Encoding: identity\r\n\r\n{{TOTP}}"),
                new RequestReplacementRule("{{TOTP}}", false, true), "123456").replacementCount());
        assertEquals(1, HttpRequestRewriter.rewrite(toRequestBytes("POST / HTTP/1.1\r\nX-OTP: {{TOTP}}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
                new RequestReplacementRule("{{TOTP}}", false, false), "123456").replacementCount());
    }

    @Test
    void rejectsMalformedFraming() {
        assertThrows(IllegalArgumentException.class, () -> HttpRequestRewriter.rewrite(toRequestBytes("not HTTP"),
                new RequestReplacementRule("otp", false, true), "123456"));
        assertThrows(IllegalArgumentException.class, () -> HttpRequestRewriter.rewrite(toRequestBytes("GET / HTTP/1.1\r\n\r\nbody"),
                new RequestReplacementRule("\r\n", false, false), "123456"));
    }
}
