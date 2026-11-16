package googleauthenticator.gui;

import googleauthenticator.session.AuthenticatorSession;

import net.miginfocom.swing.MigLayout;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import javax.swing.Timer;

/** Assembles the interface and coordinates session commands and display refreshes. */
public final class AuthenticatorPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient AuthenticatorSession session;
    private final Timer refreshTimer;

    private final ConfigurationPanel configurationPanel;
    private final CurrentCodePanel currentCodePanel = new CurrentCodePanel(this::copyCurrentCode);
    private final JLabel statusLabel = new JLabel();
    private final JLabel errorLabel = new JLabel(" ");
    private final JButton startButton = new JButton("Apply & start");
    private final JButton stopButton = new JButton("Stop");

    private boolean disposed;

    public AuthenticatorPanel(AuthenticatorSession session, Consumer<Component> applyTheme) {
        super(new BorderLayout());
        this.session = session;
        configurationPanel =
                new ConfigurationPanel(this::pauseSessionForEdit, this::startSession, applyTheme);
        statusLabel.setVisible(false);
        errorLabel.setVisible(false);
        add(createContentScrollPane(), BorderLayout.CENTER);
        // The panel and later pop-up windows share Burp's theme callback.
        applyTheme.accept(this);
        currentCodePanel.configureAppearance();
        // Burp supplies orange, hover, focus and disabled states for the primary action.
        startButton.putClientProperty("FlatLaf.styleClass", "primary");
        startButton.addActionListener(event -> startSession());
        stopButton.addActionListener(event -> stopSession("Paused. Requests are left unchanged."));
        refreshTimer = new Timer(250, event -> refreshDisplay());
        refreshDisplay();
        refreshTimer.start();
    }

    public void dispose() {
        disposed = true;
        refreshTimer.stop();
        session.stop();
        configurationPanel.clearSecret();
        refreshDisplay();
    }

    private JScrollPane createContentScrollPane() {
        JPanel contentPanel =
                new JPanel(
                        new MigLayout(
                                "fill, insets 0, gap 0", "[pref!][1!][grow,fill]", "[grow,fill]"));
        contentPanel.add(currentCodePanel, "growy");
        contentPanel.add(new JSeparator(SwingConstants.VERTICAL), "growy");
        contentPanel.add(createSettingsPanel());
        JScrollPane scroll = new JScrollPane(contentPanel);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);

        return scroll;
    }

    private JPanel createSettingsPanel() {
        JPanel panel =
                new JPanel(
                        new MigLayout(
                                "fillx, insets 24, wrap 1, gapy 0, hidemode 3", "[grow,fill]"));
        panel.add(configurationPanel, "wrap 24");
        panel.add(new JSeparator(), "wrap 24");
        panel.add(createActionPanel(), "wrap 24");
        panel.add(new SessionRuleHelpPanel());

        return panel;
    }

    private JPanel createActionPanel() {
        JPanel panel =
                new JPanel(
                        new MigLayout(
                                "fillx, insets 0, wrap 1, gap 12 6, hidemode 3", "[grow,fill]"));
        panel.add(startButton, "split 3, growx 0, wmin 150, hmin 34");
        panel.add(stopButton, "growx 0, wmin 95, hmin 34, gapleft 12");
        JButton clearSecretButton = new JButton("Clear secret");
        clearSecretButton.putClientProperty(
                "FlatLaf.style",
                "background: $Panel.background; foreground: $Label.foreground; borderColor: $Component.borderColor");
        clearSecretButton.addActionListener(event -> {
            configurationPanel.clearSecret();
            stopSession("Secret cleared. Requests are left unchanged.");
        });
        panel.add(clearSecretButton, "growx 0, wmin 140, hmin 34, gapleft 12, gapright push");
        panel.add(statusLabel, "wmin 0");
        panel.add(errorLabel, "wmin 0");

        return panel;
    }

    private void startSession() {
        if (disposed) {
            return;
        }
        session.stop();
        try {
            var generator = configurationPanel.readGenerator();
            var replacementRule = configurationPanel.readReplacementRule();
            configurationPanel.showGeneratorOptions(generator);
            session.start(generator, replacementRule);
            showStatus(
                    "Active. Only requests covered by your Burp session handling rule will be updated.");
        } catch (IllegalArgumentException | IllegalStateException e) {
            showStatus(e.getMessage());
        } catch (java.text.ParseException e) {
            showStatus("Enter a whole-number period between 1 and 300 seconds.");
        } finally {
            refreshDisplay();
        }
    }

    private void pauseSessionForEdit() {
        if (disposed) {
            return;
        }
        stopSession("Configuration changed. Apply & start to enable request updates.");
    }

    private void stopSession(String message) {
        session.stop();
        showStatus(message);
        refreshDisplay();
    }

    private void refreshDisplay() {
        var activeConfiguration = session.getActiveConfiguration();
        long updatedRequestCount = session.getUpdatedRequestCount();
        if (activeConfiguration != null) {
            try {
                currentCodePanel.showCode(
                        activeConfiguration.generator(),
                        session.getCurrentTime(),
                        updatedRequestCount);
            } catch (IllegalArgumentException | IllegalStateException e) {
                session.stop();
                showStatus(e.getMessage());
                activeConfiguration = null;
            }
        }
        boolean sessionRunning = activeConfiguration != null;
        stopButton.setEnabled(sessionRunning);
        if (!sessionRunning) {
            currentCodePanel.showPaused(updatedRequestCount);
        }
        String lastError = session.getLastError();
        errorLabel.setText(lastError == null ? " " : lastError);
        errorLabel.setToolTipText(lastError);
        errorLabel.setVisible(lastError != null);
    }

    private void showStatus(String message) {
        statusLabel.setText(message);
        statusLabel.setToolTipText(message);
        statusLabel.setVisible(message != null && !message.isBlank());
    }

    private void copyCurrentCode() {
        var activeConfiguration = session.getActiveConfiguration();
        if (activeConfiguration == null) {
            return;
        }
        try {
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(
                            new StringSelection(
                                    activeConfiguration
                                            .generator()
                                            .generateCode(session.getCurrentTime())),
                            null);
            showStatus("Code copied to the system clipboard. Request updates remain active.");
        } catch (IllegalStateException | java.awt.HeadlessException | SecurityException e) {
            showStatus("Clipboard unavailable. You can read the current code above.");
        }
    }
}
