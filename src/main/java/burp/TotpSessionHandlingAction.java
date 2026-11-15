package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import googleauthenticator.session.SessionState;

public final class TotpSessionHandlingAction implements SessionHandlingAction {
    private final SessionState state;

    TotpSessionHandlingAction(SessionState state) {
        this.state = state;
    }

    @Override
    public String name() {
        return AuthenticatorExtension.ACTION_NAME;
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData data) {
        HttpRequest request = data.request();
        var result = state.rewrite(request.toByteArray().getBytes());
        if (result.matches() == 0) {
            return ActionResult.actionResult(request);
        }
        return ActionResult.actionResult(HttpRequest.httpRequest(request.httpService(),
                ByteArray.byteArray(result.request())));
    }
}
