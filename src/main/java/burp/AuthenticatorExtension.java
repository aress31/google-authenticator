package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;

import googleauthenticator.gui.AuthenticatorPanel;
import googleauthenticator.session.AuthenticatorSession;

import javax.swing.SwingUtilities;

public final class AuthenticatorExtension implements BurpExtension {
    private static final String EXTENSION_NAME = "Google Authenticator";
    // Preserve the original action name so existing session rules can be reselected easily.
    static final String SESSION_ACTION_NAME =
            EXTENSION_NAME + ": 2FA code applied to selected parameter";

    private final AuthenticatorSession session = new AuthenticatorSession();

    private AuthenticatorPanel panel;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName(EXTENSION_NAME);
        var userInterface = montoyaApi.userInterface();
        try {
            // Swing controls need the UI thread; AuthenticatorSession and its clock do not.
            // Burp does not guarantee which thread calls initialize(), and invokeAndWait()
            // must only be called when we are not already on the UI thread.
            if (SwingUtilities.isEventDispatchThread()) {
                initializeInterface(userInterface);
            } else {
                SwingUtilities.invokeAndWait(() -> initializeInterface(userInterface));
            }
            montoyaApi.extension().registerUnloadingHandler(this::shutdown);
            montoyaApi.http().registerSessionHandlingAction(new TotpSessionHandlingAction(session));
        } catch (Exception e) {
            shutdown();
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

    private void initializeInterface(UserInterface userInterface) {
        // The panel applies Burp's theme before its display styling and reuses this callback
        // for the "Test rule" pop-up windows, which are created later.
        panel = new AuthenticatorPanel(session, userInterface::applyThemeToComponent);
        userInterface.registerSuiteTab(EXTENSION_NAME, panel);
    }

    private void shutdown() {
        session.close();
        SwingUtilities.invokeLater(() -> {
            if (panel != null) {
                panel.dispose();
            }
        });
    }
}
