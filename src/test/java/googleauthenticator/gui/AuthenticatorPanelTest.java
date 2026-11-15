package googleauthenticator.gui;

import static org.junit.jupiter.api.Assertions.*;

import googleauthenticator.session.SessionState;
import java.awt.Component;
import java.awt.Container;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;

class AuthenticatorPanelTest {
    @Test
    void validatesStartsPausesOnEditStopsAndClearsSecrets() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            SessionState state = new SessionState();
            AuthenticatorPanel panel = new AuthenticatorPanel(state);
            try {
                JButton start = (JButton) find(panel, "start");
                JButton stop = (JButton) find(panel, "stop");
                JPasswordField secret = (JPasswordField) find(panel, "secret");
                JTextField expression = (JTextField) find(panel, "expression");
                JLabel status = (JLabel) find(panel, "status");
                assertNotEquals(0, secret.getEchoChar());
                assertFalse(stop.isEnabled());
                start.doClick();
                assertNull(state.configuration());
                assertTrue(status.getText().contains("Base32"));
                secret.setText("JBSWY3DPEHPK3PXP");
                start.doClick();
                assertNotNull(state.configuration());
                assertTrue(stop.isEnabled());
                assertTrue(((JLabel) find(panel, "code")).getText().matches("\\d{3} \\d{3}"));
                ((JTextField) find(panel, "periodInput")).setText("60");
                assertNull(state.configuration());
                start.doClick();
                assertEquals(60, state.configuration().totp().period());
                expression.setText("otp.placeholder");
                assertNull(state.configuration());
                assertEquals("------", ((JLabel) find(panel, "code")).getText());
                start.doClick();
                stop.doClick();
                assertNull(state.configuration());
                start.doClick();
                ((JCheckBox) find(panel, "regex")).doClick();
                expression.setText("[");
                start.doClick();
                assertNull(state.configuration());
                assertTrue(status.getText().contains("Invalid regular expression"));
                ((JButton) find(panel, "clear")).doClick();
                assertEquals(0, secret.getPassword().length);
            } finally {
                panel.dispose();
            }
            assertNull(state.configuration());
        });
    }

    @Test
    void importsUriOptionsAndCannotRestartAfterDisposal() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            SessionState state = new SessionState();
            AuthenticatorPanel panel = new AuthenticatorPanel(state);
            try {
                ((JPasswordField) find(panel, "secret")).setText("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256");
                ((JButton) find(panel, "start")).doClick();
                assertNotNull(state.configuration());
                assertEquals(8, state.configuration().totp().digits());
                assertEquals(60, state.configuration().totp().period());
                panel.dispose();
                ((JButton) find(panel, "start")).doClick();
                assertNull(state.configuration());
                assertEquals(0, ((JPasswordField) find(panel, "secret")).getPassword().length);
            } finally {
                panel.dispose();
            }
        });
    }

    static Component find(Container root, String name) {
        for (Component child : root.getComponents()) {
            if (name.equals(child.getName())) { return child; }
            if (child instanceof Container container) {
                Component found = find(container, name);
                if (found != null) { return found; }
            }
        }
        return null;
    }
}
