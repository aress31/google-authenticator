package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import googleauthenticator.session.AuthenticatorSession;

public final class TotpSessionHandlingAction implements SessionHandlingAction {
    private final AuthenticatorSession session;

    TotpSessionHandlingAction(AuthenticatorSession session) {
        this.session = session;
    }

    @Override
    public String name() {
        return AuthenticatorExtension.SESSION_ACTION_NAME;
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {
        HttpRequest request = actionData.request();
        var rewriteResult = session.rewrite(request.toByteArray().getBytes());
        if (rewriteResult.replacementCount() == 0) {
            return ActionResult.actionResult(request);
        }
        return ActionResult.actionResult(HttpRequest.httpRequest(request.httpService(),
                ByteArray.byteArray(rewriteResult.requestBytes())));
    }
}
