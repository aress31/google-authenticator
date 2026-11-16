package googleauthenticator.session;

import lombok.AccessLevel;
import lombok.Getter;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** A compiled request replacement rule. A named group 'otp' limits replacement to that group. */
public final class RequestReplacementRule {
    public record ReplacementResult(String text, int replacementCount) {}

    private final Pattern pattern;

    @Getter(AccessLevel.PACKAGE)
    private final boolean bodyOnly;

    private final int replacementGroupIndex;

    public RequestReplacementRule(
            String matchExpression, boolean regularExpression, boolean bodyOnly) {
        if (matchExpression == null || matchExpression.isEmpty()) {
            throw new IllegalArgumentException(
                    "Enter a non-empty placeholder or regular expression.");
        }
        try {
            pattern = Pattern.compile(matchExpression, regularExpression ? 0 : Pattern.LITERAL);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regular expression: " + e.getDescription());
        }
        if (pattern.matcher("").find()) {
            throw new IllegalArgumentException("The expression must match a non-empty value.");
        }
        this.bodyOnly = bodyOnly;
        // Group 0 is the whole match when the rule has no named 'otp' group.
        replacementGroupIndex = pattern.namedGroups().getOrDefault("otp", 0);
    }

    public ReplacementResult replaceMatches(String input, String code) {
        Matcher matcher = pattern.matcher(input);
        if (!matcher.find()) {
            return new ReplacementResult(input, 0);
        }
        StringBuilder rewrittenText = new StringBuilder();
        int previousEnd = 0;
        int replacementCount = 0;
        do {
            int matchStart = matcher.start(replacementGroupIndex);
            int matchEnd = matcher.end(replacementGroupIndex);
            if (matchStart < 0) {
                continue; // An optional named group did not participate.
            }
            if (matchStart == matchEnd) {
                throw new IllegalArgumentException(
                        "The expression matched an empty value; request left unchanged.");
            }
            rewrittenText.append(input, previousEnd, matchStart).append(code);
            previousEnd = matchEnd;
            replacementCount++;
        } while (matcher.find());

        return new ReplacementResult(
                rewrittenText.append(input, previousEnd, input.length()).toString(),
                replacementCount);
    }
}
