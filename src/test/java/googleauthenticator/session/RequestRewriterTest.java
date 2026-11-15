package googleauthenticator.session;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RequestRewriterTest {
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.ISO_8859_1); }
    private static String string(byte[] value) { return new String(value, StandardCharsets.ISO_8859_1); }

    @Test
    void literalModeTreatsRegexMetacharactersLiterally() {
        var rule = new MatchRule("[otp].*", false, true);
        assertEquals("x123456y [otp]other", rule.replace("x[otp].*y [otp]other", "123456").value());
    }

    @Test
    void namedCapturePreservesSurroundingJsonAndReplacesAllValues() {
        var rule = new MatchRule("\"pin\":\"(?<otp>\\d{6,8})\"", true, true);
        var result = rule.replace("{\"pin\":\"000000\",\"n\":123456,\"pin\":\"98765432\"}", "081804");
        assertEquals("{\"pin\":\"081804\",\"n\":123456,\"pin\":\"081804\"}", result.value());
        assertEquals(2, result.matches());
    }

    @Test
    void wholeMatchRegexAndOptionalCapture() {
        assertEquals("a=123456&b=123456", new MatchRule("\\d{6,8}", true, true)
                .replace("a=111111&b=22222222", "123456").value());
        assertEquals("other 123456", new MatchRule("other|(?<otp>value)", true, true)
                .replace("other value", "123456").value());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "[", "a*", "^", "(?<otp>)"})
    void invalidOrEmptyExpressionsCannotBeEnabled(String expression) {
        assertThrows(IllegalArgumentException.class, () -> new MatchRule(expression, true, true));
    }

    @Test
    void emptyMatchesFoundOnlyAtRuntimeAreRejected() {
        var rule = new MatchRule("(?=a)", true, true);
        assertThrows(IllegalArgumentException.class, () -> rule.replace("a", "123456"));
    }

    @Test
    void updatesBodyAndRepairsAllContentLengthsWhilePreservingBinaryBytes() {
        String request = "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10\r\ncontent-length: 10\r\n"
                + "X-Keep: {{TOTP}}\r\n\r\n\u00ff\u0000{{TOTP}}";
        var result = RequestRewriter.rewrite(bytes(request), new MatchRule("{{TOTP}}", false, true), "081804");
        assertEquals("POST / HTTP/1.1\r\nHost: example.test\r\nX-Keep: {{TOTP}}\r\nContent-Length: 8\r\n\r\n\u00ff\u0000081804",
                string(result.request()));
        assertEquals(1, result.matches());
    }

    @Test
    void noMatchOrSameCodeLeavesBytesUntouched() {
        byte[] request = bytes("GET / HTTP/1.1\r\nHost: test\r\n\r\n");
        var result = RequestRewriter.rewrite(request, new MatchRule("{{TOTP}}", false, true), "123456");
        assertSame(request, result.request());
        assertEquals(0, result.matches());
        assertEquals(0, RequestRewriter.rewrite(bytes("POST / HTTP/1.1\r\n\r\n123456"),
                new MatchRule("123456", false, true), "123456").matches());
    }

    @Test
    void wholeRequestModeCanReplaceHeaderAndQueryValues() {
        var result = RequestRewriter.rewrite(bytes("GET /?otp={{TOTP}} HTTP/1.1\r\nX-OTP: {{TOTP}}\r\n\r\n"),
                new MatchRule("{{TOTP}}", false, false), "123456");
        assertEquals("GET /?otp=123456 HTTP/1.1\r\nX-OTP: 123456\r\n\r\n", string(result.request()));
        assertEquals(2, result.matches());
    }

    @Test
    void wholeRequestModeAlsoRepairsBodyLength() {
        var result = RequestRewriter.rewrite(bytes("POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\n{{TOTP}}"),
                new MatchRule("{{TOTP}}", false, false), "123456");
        assertTrue(string(result.request()).contains("Content-Length: 6\r\n\r\n123456"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Transfer-Encoding: chunked", "Transfer-Encoding: gzip", "Content-Encoding: gzip", "Content-Encoding: br"})
    void rejectsEncodedBodyChanges(String encoding) {
        assertThrows(IllegalArgumentException.class, () -> RequestRewriter.rewrite(
                bytes("POST / HTTP/1.1\r\n" + encoding + "\r\n\r\n{{TOTP}}"),
                new MatchRule("{{TOTP}}", false, true), "123456"));
    }

    @Test
    void permitsIdentityEncodingAndHeaderOnlyChangesOnEncodedMessages() {
        assertEquals(1, RequestRewriter.rewrite(bytes("POST / HTTP/1.1\r\nContent-Encoding: identity\r\n\r\n{{TOTP}}"),
                new MatchRule("{{TOTP}}", false, true), "123456").matches());
        assertEquals(1, RequestRewriter.rewrite(bytes("POST / HTTP/1.1\r\nX-OTP: {{TOTP}}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
                new MatchRule("{{TOTP}}", false, false), "123456").matches());
    }

    @Test
    void rejectsMalformedFraming() {
        assertThrows(IllegalArgumentException.class, () -> RequestRewriter.rewrite(bytes("not HTTP"),
                new MatchRule("otp", false, true), "123456"));
        assertThrows(IllegalArgumentException.class, () -> RequestRewriter.rewrite(bytes("GET / HTTP/1.1\r\n\r\nbody"),
                new MatchRule("\r\n", false, false), "123456"));
    }
}
