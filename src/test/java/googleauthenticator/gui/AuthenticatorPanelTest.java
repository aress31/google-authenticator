package googleauthenticator.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import googleauthenticator.session.AuthenticatorSession;
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
            AuthenticatorSession session = new AuthenticatorSession();
            AuthenticatorPanel authenticatorPanel = new AuthenticatorPanel(session);
            try {
                JButton startButton = (JButton) findComponentByName(authenticatorPanel, "startButton");
                JButton stopButton = (JButton) findComponentByName(authenticatorPanel, "stopButton");
                JPasswordField sharedSecretField = (JPasswordField) findComponentByName(authenticatorPanel, "sharedSecretField");
                JTextField matchExpressionField = (JTextField) findComponentByName(authenticatorPanel, "matchExpressionField");
                JLabel statusLabel = (JLabel) findComponentByName(authenticatorPanel, "statusLabel");
                assertNotEquals(0, sharedSecretField.getEchoChar());
                assertFalse(stopButton.isEnabled());
                startButton.doClick();
                assertNull(session.getActiveConfiguration());
                assertTrue(statusLabel.getText().contains("Base32"));
                sharedSecretField.setText("JBSWY3DPEHPK3PXP");
                startButton.doClick();
                assertNotNull(session.getActiveConfiguration());
                assertTrue(stopButton.isEnabled());
                assertTrue(((JLabel) findComponentByName(authenticatorPanel, "codeLabel")).getText().matches("\\d{3} \\d{3}"));
                ((JTextField) findComponentByName(authenticatorPanel, "periodField")).setText("60");
                assertNull(session.getActiveConfiguration());
                startButton.doClick();
                assertEquals(60, session.getActiveConfiguration().generator().getPeriodSeconds());
                matchExpressionField.setText("otp.placeholder");
                assertNull(session.getActiveConfiguration());
                assertEquals("------", ((JLabel) findComponentByName(authenticatorPanel, "codeLabel")).getText());
                startButton.doClick();
                stopButton.doClick();
                assertNull(session.getActiveConfiguration());
                startButton.doClick();
                ((JCheckBox) findComponentByName(authenticatorPanel, "regexCheckBox")).doClick();
                matchExpressionField.setText("[");
                startButton.doClick();
                assertNull(session.getActiveConfiguration());
                assertTrue(statusLabel.getText().contains("Invalid regular expression"));
                ((JButton) findComponentByName(authenticatorPanel, "clearSecretButton")).doClick();
                assertEquals(0, sharedSecretField.getPassword().length);
            } finally {
                authenticatorPanel.dispose();
            }
            assertNull(session.getActiveConfiguration());
        });
    }

    @Test
    void importsUriOptionsAndCannotRestartAfterDisposal() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AuthenticatorSession session = new AuthenticatorSession();
            AuthenticatorPanel authenticatorPanel = new AuthenticatorPanel(session);
            try {
                ((JPasswordField) findComponentByName(authenticatorPanel, "sharedSecretField")).setText("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256");
                ((JButton) findComponentByName(authenticatorPanel, "startButton")).doClick();
                assertNotNull(session.getActiveConfiguration());
                assertEquals(8, session.getActiveConfiguration().generator().getCodeLength());
                assertEquals(60, session.getActiveConfiguration().generator().getPeriodSeconds());
                authenticatorPanel.dispose();
                ((JButton) findComponentByName(authenticatorPanel, "startButton")).doClick();
                assertNull(session.getActiveConfiguration());
                assertEquals(0, ((JPasswordField) findComponentByName(authenticatorPanel, "sharedSecretField")).getPassword().length);
            } finally {
                authenticatorPanel.dispose();
            }
        });
    }

    static Component findComponentByName(Container container, String name) {
        for (Component child : container.getComponents()) {
            if (name.equals(child.getName())) { return child; }
            if (child instanceof Container childContainer) {
                Component matchedComponent = findComponentByName(childContainer, name);
                if (matchedComponent != null) { return matchedComponent; }
            }
        }
        return null;
    }
}
