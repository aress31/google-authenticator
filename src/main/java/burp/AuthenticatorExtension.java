package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import googleauthenticator.gui.AuthenticatorPanel;
import googleauthenticator.session.SessionState;
import javax.swing.SwingUtilities;

public final class AuthenticatorExtension implements BurpExtension {
    public static final String NAME = "Google Authenticator";
    // Preserve the original action name so existing session rules can be reselected easily.
    public static final String ACTION_NAME = NAME + ": 2FA code applied to selected parameter";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        SessionState state = new SessionState();
        AuthenticatorPanel[] panel = new AuthenticatorPanel[1];
        try {
            Runnable initializeUi = () -> {
                panel[0] = new AuthenticatorPanel(state);
                api.userInterface().applyThemeToComponent(panel[0]);
                api.userInterface().registerSuiteTab(NAME, panel[0]);
            };
            if (SwingUtilities.isEventDispatchThread()) {
                initializeUi.run();
            } else {
                SwingUtilities.invokeAndWait(initializeUi);
            }
        } catch (Exception e) {
            state.close();
            if (panel[0] != null) {
                SwingUtilities.invokeLater(panel[0]::dispose);
            }
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            api.logging().logToError("Google Authenticator could not initialize its interface.");
            return;
        }
        api.http().registerSessionHandlingAction(new TotpSessionHandlingAction(state));
        api.extension().registerUnloadingHandler(() -> {
            state.close();
            SwingUtilities.invokeLater(panel[0]::dispose);
        });
        api.logging().logToOutput(NAME + " 2.0.0 initialized. Secrets are held in memory only.");
    }
}
