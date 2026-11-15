package googleauthenticator.session;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** A compiled request replacement rule. A named group 'otp' limits replacement to that group. */
public final class RequestReplacementRule {
    private final Pattern pattern;
    private final boolean bodyOnly;
    private final boolean hasOtpCaptureGroup;

    public RequestReplacementRule(String matchExpression, boolean regularExpression, boolean bodyOnly) {
        if (matchExpression == null || matchExpression.isEmpty()) {
            throw new IllegalArgumentException("Enter a non-empty placeholder or regular expression.");
        }
        try {
            pattern = Pattern.compile(regularExpression ? matchExpression : Pattern.quote(matchExpression));
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regular expression: " + e.getDescription());
        }
        if (pattern.matcher("").find()) {
            throw new IllegalArgumentException("The expression must match a non-empty value.");
        }
        this.bodyOnly = bodyOnly;
        hasOtpCaptureGroup = regularExpression && pattern.namedGroups().containsKey("otp");
    }

    public boolean isBodyOnly() {
        return bodyOnly;
    }

    public ReplacementResult replaceMatches(String input, String code) {
        Matcher matcher = pattern.matcher(input);
        StringBuilder rewrittenText = new StringBuilder();
        int previousEnd = 0;
        int replacementCount = 0;
        while (matcher.find()) {
            int matchStart = hasOtpCaptureGroup ? matcher.start("otp") : matcher.start();
            int matchEnd = hasOtpCaptureGroup ? matcher.end("otp") : matcher.end();
            if (matchStart < 0) {
                continue; // An optional named group did not participate.
            }
            if (matchStart == matchEnd) {
                throw new IllegalArgumentException("The expression matched an empty value; request left unchanged.");
            }
            rewrittenText.append(input, previousEnd, matchStart).append(code);
            previousEnd = matchEnd;
            replacementCount++;
        }
        return new ReplacementResult(rewrittenText.append(input, previousEnd, input.length()).toString(), replacementCount);
    }

    public record ReplacementResult(String text, int replacementCount) { }
}
