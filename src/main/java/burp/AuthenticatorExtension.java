package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import googleauthenticator.gui.AuthenticatorPanel;
import googleauthenticator.session.AuthenticatorSession;
import javax.swing.SwingUtilities;

public final class AuthenticatorExtension implements BurpExtension {
    public static final String EXTENSION_NAME = "Google Authenticator";
    // Preserve the original action name so existing session rules can be reselected easily.
    public static final String SESSION_ACTION_NAME = EXTENSION_NAME + ": 2FA code applied to selected parameter";

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName(EXTENSION_NAME);
        AuthenticatorSession session = new AuthenticatorSession();
        AuthenticatorPanel[] panelHolder = new AuthenticatorPanel[1];
        try {
            Runnable initializeInterface = () -> {
                panelHolder[0] = new AuthenticatorPanel(session);
                montoyaApi.userInterface().applyThemeToComponent(panelHolder[0]);
                montoyaApi.userInterface().registerSuiteTab(EXTENSION_NAME, panelHolder[0]);
            };
            if (SwingUtilities.isEventDispatchThread()) {
                initializeInterface.run();
            } else {
                SwingUtilities.invokeAndWait(initializeInterface);
            }
        } catch (Exception e) {
            session.close();
            if (panelHolder[0] != null) {
                SwingUtilities.invokeLater(panelHolder[0]::dispose);
            }
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            montoyaApi.logging().logToError("Google Authenticator could not initialize its interface.");
            return;
        }
        montoyaApi.http().registerSessionHandlingAction(new TotpSessionHandlingAction(session));
        montoyaApi.extension().registerUnloadingHandler(() -> {
            session.close();
            SwingUtilities.invokeLater(panelHolder[0]::dispose);
        });
        montoyaApi.logging().logToOutput(EXTENSION_NAME + " 2.0.0 initialized. Secrets are held in memory only.");
    }
}
