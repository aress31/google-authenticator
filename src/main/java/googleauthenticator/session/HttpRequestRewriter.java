package googleauthenticator.session;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

/** Byte-preserving HTTP/1 representation, as exposed by Montoya for HTTP/1 and HTTP/2. */
public final class HttpRequestRewriter {
    private static final Pattern CONTENT_LENGTH_HEADER_PATTERN =
            Pattern.compile("(?im)^Content-Length:[^\\r\\n]*\\r\\n");
    private static final Pattern TRANSFER_ENCODING_HEADER_PATTERN =
            Pattern.compile("(?im)^Transfer-Encoding:");
    private static final Pattern CONTENT_ENCODING_HEADER_PATTERN =
            Pattern.compile("(?im)^Content-Encoding:([^\\r\\n]*)");

    private HttpRequestRewriter() {}

    public static RewriteResult rewrite(
            byte[] requestBytes, RequestReplacementRule replacementRule, String code) {
        // ISO-8859-1 maps each byte to exactly one char, including binary bodies.
        String originalRequest = new String(requestBytes, StandardCharsets.ISO_8859_1);
        int bodyBoundary = originalRequest.indexOf("\r\n\r\n");
        if (bodyBoundary < 0) {
            throw new IllegalArgumentException(
                    "Request has no HTTP header/body boundary; left unchanged.");
        }
        String originalHeaders = originalRequest.substring(0, bodyBoundary + 2);
        String originalBody = originalRequest.substring(bodyBoundary + 4);
        RequestReplacementRule.ReplacementResult replacementResult =
                replacementRule.replaceMatches(
                        replacementRule.isBodyOnly() ? originalBody : originalRequest, code);
        if (replacementResult.replacementCount() == 0) {
            return new RewriteResult(requestBytes, 0);
        }
        String rewrittenRequest =
                replacementRule.isBodyOnly()
                        ? originalHeaders + "\r\n" + replacementResult.text()
                        : replacementResult.text();
        int rewrittenBodyBoundary = rewrittenRequest.indexOf("\r\n\r\n");
        if (rewrittenBodyBoundary < 0) {
            throw new IllegalArgumentException(
                    "The rule changed HTTP framing; request left unchanged.");
        }
        String rewrittenHeaders = rewrittenRequest.substring(0, rewrittenBodyBoundary + 2);
        String rewrittenBody = rewrittenRequest.substring(rewrittenBodyBoundary + 4);
        if (!originalBody.equals(rewrittenBody)) {
            if (TRANSFER_ENCODING_HEADER_PATTERN.matcher(originalHeaders).find()
                    || TRANSFER_ENCODING_HEADER_PATTERN.matcher(rewrittenHeaders).find()
                    || hasEncodedBody(originalHeaders)
                    || hasEncodedBody(rewrittenHeaders)) {
                throw new IllegalArgumentException(
                        "Encoded or transfer-encoded bodies are not rewritten; request left unchanged.");
            }
            rewrittenHeaders =
                    CONTENT_LENGTH_HEADER_PATTERN.matcher(rewrittenHeaders).replaceAll("");
            rewrittenHeaders += "Content-Length: " + rewrittenBody.length() + "\r\n";
        }
        byte[] rewrittenBytes =
                (rewrittenHeaders + "\r\n" + rewrittenBody).getBytes(StandardCharsets.ISO_8859_1);
        return new RewriteResult(
                rewrittenBytes,
                Arrays.equals(requestBytes, rewrittenBytes)
                        ? 0
                        : replacementResult.replacementCount());
    }

    public record RewriteResult(byte[] requestBytes, int replacementCount) {}

    private static boolean hasEncodedBody(String originalHeaders) {
        return CONTENT_ENCODING_HEADER_PATTERN
                .matcher(originalHeaders)
                .results()
                .anyMatch(encodingHeader ->
                        !"identity".equalsIgnoreCase(encodingHeader.group(1).strip()));
    }
}
