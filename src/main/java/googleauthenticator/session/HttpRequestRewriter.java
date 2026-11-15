package googleauthenticator.session;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Applies replacement rules while Montoya manages HTTP parsing and body-length updates. */
final class HttpRequestRewriter {
    private HttpRequestRewriter() {}

    /** Returns the original request when unchanged, or a modified Montoya request. */
    static HttpRequest rewrite(
            HttpRequest request, RequestReplacementRule replacementRule, String code) {
        ByteArray requestData = request.toByteArray();
        validateFraming(requestData);
        ByteArray originalBody = request.body();
        ByteArray target = replacementRule.isBodyOnly() ? originalBody : requestData;
        // Map each byte to one character so matching preserves binary body data.
        String input = new String(target.getBytes(), StandardCharsets.ISO_8859_1);
        var replacementResult = replacementRule.replaceMatches(input, code);
        if (replacementResult.replacementCount() == 0 || input.equals(replacementResult.text())) {
            return request;
        }

        ByteArray replacement =
                ByteArray.byteArray(replacementResult.text().getBytes(StandardCharsets.ISO_8859_1));
        if (!replacementRule.isBodyOnly()) {
            validateFraming(replacement);
        }
        HttpRequest rewrittenRequest =
                replacementRule.isBodyOnly()
                        ? request
                        : HttpRequest.httpRequest(request.httpService(), replacement);
        ByteArray rewrittenBody =
                replacementRule.isBodyOnly() ? replacement : rewrittenRequest.body();
        if (!Arrays.equals(originalBody.getBytes(), rewrittenBody.getBytes())) {
            if (hasEncodedBody(request) || hasEncodedBody(rewrittenRequest)) {
                throw new IllegalArgumentException(
                        "Encoded or transfer-encoded bodies are not rewritten; request left unchanged.");
            }
            rewrittenRequest = rewrittenRequest.withBody(rewrittenBody);
        }
        return rewrittenRequest;
    }

    private static void validateFraming(ByteArray data) {
        if (data.indexOf("\r\n\r\n") < 0) {
            throw new IllegalArgumentException(
                    "Request has no HTTP header/body boundary; left unchanged.");
        }
    }

    private static boolean hasEncodedBody(HttpRequest request) {
        return request.hasHeader("Transfer-Encoding")
                || request.headers().stream()
                        .anyMatch(header ->
                                header.name().equalsIgnoreCase("Content-Encoding")
                                        && !"identity".equalsIgnoreCase(header.value().strip()));
    }
}
