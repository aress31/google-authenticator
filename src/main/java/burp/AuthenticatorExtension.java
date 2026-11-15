package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;

import googleauthenticator.gui.AuthenticatorPanel;
import googleauthenticator.session.AuthenticatorSession;

import javax.swing.SwingUtilities;

public final class AuthenticatorExtension implements BurpExtension {
    public static final String EXTENSION_NAME = "Google Authenticator";
    // Preserve the original action name so existing session rules can be reselected easily.
    public static final String SESSION_ACTION_NAME =
            EXTENSION_NAME + ": 2FA code applied to selected parameter";

    private AuthenticatorPanel panel;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName(EXTENSION_NAME);
        AuthenticatorSession session = new AuthenticatorSession();
        var userInterface = montoyaApi.userInterface();
        try {
            // Create Swing controls on the event thread before registering the session action.
            if (SwingUtilities.isEventDispatchThread()) {
                initializeInterface(session, userInterface);
            } else {
                SwingUtilities.invokeAndWait(() -> initializeInterface(session, userInterface));
            }
            montoyaApi
                    .extension()
                    .registerUnloadingHandler(() -> {
                        session.close();
                        SwingUtilities.invokeLater(() -> panel.dispose());
                    });
            montoyaApi.http().registerSessionHandlingAction(new TotpSessionHandlingAction(session));
        } catch (Exception e) {
            session.close();
            SwingUtilities.invokeLater(() -> {
                if (panel != null) {
                    panel.dispose();
                }
            });
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            montoyaApi.logging().logToError("Google Authenticator could not initialize.", e);
            return;
        }
        montoyaApi
                .logging()
                .logToOutput(
                        EXTENSION_NAME + " 2.0.0 initialized. Secrets are held in memory only.");
    }

    private void initializeInterface(AuthenticatorSession session, UserInterface userInterface) {
        // The theme call below styles the panel's existing controls; this callback styles
        // the "Test rule" pop-up windows, which are created later.
        panel = new AuthenticatorPanel(session, userInterface::applyThemeToComponent);
        userInterface.applyThemeToComponent(panel);
        userInterface.registerSuiteTab(EXTENSION_NAME, panel);
    }
}
