package burp;

import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

import googleauthenticator.session.AuthenticatorSession;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
final class TotpSessionHandlingAction implements SessionHandlingAction {
    private final AuthenticatorSession session;

    @Override
    public String name() {
        return AuthenticatorExtension.SESSION_ACTION_NAME;
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {
        return ActionResult.actionResult(session.rewrite(actionData.request()));
    }
}
