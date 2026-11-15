package googleauthenticator.session;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** A compiled rule. An optional named group 'otp' limits replacement to that group. */
public final class MatchRule {
    private final Pattern pattern;
    private final boolean bodyOnly;
    private final boolean capture;

    public MatchRule(String expression, boolean regex, boolean bodyOnly) {
        if (expression == null || expression.isEmpty()) {
            throw new IllegalArgumentException("Enter a non-empty placeholder or regular expression.");
        }
        try {
            pattern = Pattern.compile(regex ? expression : Pattern.quote(expression));
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regular expression: " + e.getDescription());
        }
        if (pattern.matcher("").find()) {
            throw new IllegalArgumentException("The expression must match a non-empty value.");
        }
        this.bodyOnly = bodyOnly;
        capture = regex && pattern.namedGroups().containsKey("otp");
    }

    public boolean bodyOnly() { return bodyOnly; }

    public Replacement replace(String input, String code) {
        Matcher matcher = pattern.matcher(input);
        StringBuilder result = new StringBuilder();
        int previous = 0;
        int count = 0;
        while (matcher.find()) {
            int start = capture ? matcher.start("otp") : matcher.start();
            int end = capture ? matcher.end("otp") : matcher.end();
            if (start < 0) {
                continue; // An optional named group did not participate.
            }
            if (start == end) {
                throw new IllegalArgumentException("The expression matched an empty value; request left unchanged.");
            }
            result.append(input, previous, start).append(code);
            previous = end;
            count++;
        }
        return new Replacement(result.append(input, previous, input.length()).toString(), count);
    }

    public record Replacement(String value, int matches) { }
}
