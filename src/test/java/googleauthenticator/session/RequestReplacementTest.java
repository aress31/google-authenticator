package googleauthenticator.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RequestReplacementTest {
    @Test
    void literalModeTreatsRegexMetacharactersLiterally() {
        var replacementRule = new RequestReplacementRule("[otp].*", false, true);
        assertEquals(
                "x123456y [otp]other",
                replacementRule.replaceMatches("x[otp].*y [otp]other", "123456").text());
    }

    @Test
    void namedCapturePreservesSurroundingJsonAndReplacesAllValues() {
        var replacementRule =
                new RequestReplacementRule("(\"pin\":\")(?<otp>\\d{6,8})(\")", true, true);
        var result =
                replacementRule.replaceMatches(
                        "{\"pin\":\"000000\",\"n\":123456,\"pin\":\"98765432\"}", "081804");
        assertEquals("{\"pin\":\"081804\",\"n\":123456,\"pin\":\"081804\"}", result.text());
        assertEquals(2, result.replacementCount());
    }

    @Test
    void replacesWholeMatchesAndSkipsUnmatchedOptionalCaptures() {
        assertEquals(
                "a=123456&b=123456",
                new RequestReplacementRule("\\d{6,8}", true, true)
                        .replaceMatches("a=111111&b=22222222", "123456")
                        .text());
        assertEquals(
                "other 123456",
                new RequestReplacementRule("other|(?<otp>value)", true, true)
                        .replaceMatches("other value", "123456")
                        .text());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "[", "a*"})
    void invalidOrEmptyExpressionsCannotBeEnabled(String expression) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new RequestReplacementRule(expression, true, true));
    }

    @Test
    void emptyMatchesFoundOnlyAtRuntimeAreRejected() {
        var replacementRule = new RequestReplacementRule("(?=a)", true, true);
        assertThrows(
                IllegalArgumentException.class,
                () -> replacementRule.replaceMatches("a", "123456"));
    }
}
