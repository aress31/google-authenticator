package googleauthenticator.session;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

/** Byte-preserving HTTP/1 representation, as exposed by Montoya for HTTP/1 and HTTP/2. */
public final class RequestRewriter {
    private static final Pattern LENGTH = Pattern.compile("(?im)^Content-Length:[^\\r\\n]*\\r\\n");
    private static final Pattern TRANSFER = Pattern.compile("(?im)^Transfer-Encoding:");
    private static final Pattern ENCODING = Pattern.compile("(?im)^Content-Encoding:([^\\r\\n]*)");

    private RequestRewriter() { }

    public static Result rewrite(byte[] request, MatchRule rule, String code) {
        // ISO-8859-1 maps each byte to exactly one char, including binary bodies.
        String original = new String(request, StandardCharsets.ISO_8859_1);
        int boundary = original.indexOf("\r\n\r\n");
        if (boundary < 0) {
            throw new IllegalArgumentException("Request has no HTTP header/body boundary; left unchanged.");
        }
        String headers = original.substring(0, boundary + 2);
        String body = original.substring(boundary + 4);
        MatchRule.Replacement replacement = rule.replace(rule.bodyOnly() ? body : original, code);
        if (replacement.matches() == 0) {
            return new Result(request, 0);
        }
        String rewritten = rule.bodyOnly() ? headers + "\r\n" + replacement.value() : replacement.value();
        int newBoundary = rewritten.indexOf("\r\n\r\n");
        if (newBoundary < 0) {
            throw new IllegalArgumentException("The rule changed HTTP framing; request left unchanged.");
        }
        String newHeaders = rewritten.substring(0, newBoundary + 2);
        String newBody = rewritten.substring(newBoundary + 4);
        if (!body.equals(newBody)) {
            if (TRANSFER.matcher(headers).find() || TRANSFER.matcher(newHeaders).find()
                    || isEncoded(headers) || isEncoded(newHeaders)) {
                throw new IllegalArgumentException("Encoded or transfer-encoded bodies are not rewritten; request left unchanged.");
            }
            newHeaders = LENGTH.matcher(newHeaders).replaceAll("");
            newHeaders += "Content-Length: " + newBody.length() + "\r\n";
        }
        byte[] bytes = (newHeaders + "\r\n" + newBody).getBytes(StandardCharsets.ISO_8859_1);
        return new Result(bytes, Arrays.equals(request, bytes) ? 0 : replacement.matches());
    }

    public record Result(byte[] request, int matches) { }

    private static boolean isEncoded(String headers) {
        return ENCODING.matcher(headers).results()
                .anyMatch(match -> !"identity".equalsIgnoreCase(match.group(1).strip()));
    }
}
