package googleauthenticator.gui;

import googleauthenticator.otp.TotpGenerator;
import googleauthenticator.otp.TotpInputParser;
import googleauthenticator.session.AuthenticatorSession;
import googleauthenticator.session.RequestReplacementRule;

import net.miginfocom.swing.MigLayout;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.time.Instant;
import java.util.Arrays;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Native Swing controls inherit Burp's light/dark theme and keyboard behavior.
 */
public final class AuthenticatorPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient AuthenticatorSession session;
    private final transient Consumer<Component> applyTheme;
    private final JPasswordField sharedSecretField = new JPasswordField(28);
    private final JComboBox<TotpGenerator.Algorithm> algorithmComboBox =
            new JComboBox<>(TotpGenerator.Algorithm.values());
    private final JComboBox<Integer> codeLengthComboBox = new JComboBox<>(new Integer[] {6, 8});
    private final JSpinner periodSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 300, 1));
    private final JTextField matchExpressionField = new JTextField("{{TOTP}}", 28);
    private final JCheckBox regexCheckBox = new JCheckBox("Regular expression");
    private final JCheckBox bodyOnlyCheckBox = new JCheckBox("Request body only", true);
    private final JLabel codeLabel = new JLabel("------", SwingConstants.CENTER);
    private final JLabel countdownLabel =
            new JLabel("Start to generate a code", SwingConstants.CENTER);
    private final JProgressBar expiryProgressBar = new JProgressBar(0, 30);
    private final JLabel statusLabel = new JLabel("Paused. Add your shared secret to get started.");
    private final JLabel requestCountLabel = new JLabel("0 requests updated");
    private final JLabel errorLabel = new JLabel(" ");
    private final JButton startButton = new JButton("Apply & start");
    private final JButton stopButton = new JButton("Stop");
    private final JButton copyButton = new JButton("Copy code");
    private final Timer refreshTimer;
    private boolean updatingForm;
    private boolean disposed;

    public AuthenticatorPanel(AuthenticatorSession session, Consumer<Component> applyTheme) {
        super(new BorderLayout());
        this.session = session;
        this.applyTheme = applyTheme;
        sharedSecretField
                .getAccessibleContext()
                .setAccessibleName("Shared secret or TOTP provisioning URI");
        matchExpressionField.getAccessibleContext().setAccessibleName("Expression to replace");
        algorithmComboBox.getAccessibleContext().setAccessibleName("HMAC algorithm");
        codeLengthComboBox.getAccessibleContext().setAccessibleName("Code digits");
        periodSpinner.getAccessibleContext().setAccessibleName("Period in seconds");

        JPanel contentPanel = new JPanel(new MigLayout("fillx, wrap 2", "[grow,fill][grow,fill]"));
        contentPanel.add(createAuthenticatorSettingsPanel(), "growx, top");
        contentPanel.add(createCodePanel(), "grow, wrap");
        contentPanel.add(createReplacementPanel(), "span, growx, wrap");
        contentPanel.add(createActionPanel(), "span, growx, wrap");
        contentPanel.add(createInstructionsPanel(), "span, growx, wrap");

        JScrollPane scroll = new JScrollPane(contentPanel);
        add(scroll, BorderLayout.CENTER);

        DocumentListener configurationChangeListener =
                new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent event) {
                        pauseSessionForEdit();
                    }

                    @Override
                    public void removeUpdate(DocumentEvent event) {
                        pauseSessionForEdit();
                    }

                    @Override
                    public void changedUpdate(DocumentEvent event) {
                        pauseSessionForEdit();
                    }
                };
        sharedSecretField.getDocument().addDocumentListener(configurationChangeListener);
        matchExpressionField.getDocument().addDocumentListener(configurationChangeListener);
        ((JSpinner.DefaultEditor) periodSpinner.getEditor())
                .getTextField()
                .getDocument()
                .addDocumentListener(configurationChangeListener);
        algorithmComboBox.addActionListener(event -> pauseSessionForEdit());
        codeLengthComboBox.addActionListener(event -> pauseSessionForEdit());
        periodSpinner.addChangeListener(event -> pauseSessionForEdit());
        regexCheckBox.addActionListener(event -> pauseSessionForEdit());
        bodyOnlyCheckBox.addActionListener(event -> pauseSessionForEdit());
        startButton.addActionListener(event -> startSession());
        sharedSecretField.addActionListener(event -> startSession());
        stopButton.addActionListener(event -> {
            session.stop();
            statusLabel.setText("Paused. Requests are left unchanged.");
            refreshDisplay();
        });
        copyButton.addActionListener(event -> copyCurrentCode());
        refreshTimer = new Timer(250, event -> refreshDisplay());
        refreshTimer.start();
        refreshDisplay();
    }

    private JPanel createAuthenticatorSettingsPanel() {
        JPanel panel = createSectionPanel("Authenticator");
        JLabel label = new JLabel("Shared secret or otpauth://totp URI");
        label.setLabelFor(sharedSecretField);
        panel.add(label);
        panel.add(sharedSecretField, "growx, wmin 0");
        JCheckBox showSecretCheckBox = new JCheckBox("Show secret");
        char secretEchoCharacter = sharedSecretField.getEchoChar();
        showSecretCheckBox.addActionListener(event ->
                sharedSecretField.setEchoChar(
                        showSecretCheckBox.isSelected() ? (char) 0 : secretEchoCharacter));
        panel.add(showSecretCheckBox);
        JPanel optionsPanel = new JPanel(new MigLayout("insets 0"));
        addLabeledControl(optionsPanel, "Algorithm", algorithmComboBox);
        addLabeledControl(optionsPanel, "Digits", codeLengthComboBox);
        addLabeledControl(optionsPanel, "Period (s)", periodSpinner);
        panel.add(optionsPanel);
        panel.add(new JLabel("A provisioning URI supplies its own algorithm, digits and period."));
        panel.add(new JLabel("Secrets stay in memory and are never saved to settings or logs."));
        return panel;
    }

    private JPanel createCodePanel() {
        JPanel panel =
                new JPanel(new MigLayout("fill, wrap 1", "[grow,fill]", "[grow,fill][][][]"));
        panel.setBorder(BorderFactory.createTitledBorder("Current code"));
        codeLabel.getAccessibleContext().setAccessibleName("Current one-time code");
        panel.add(codeLabel, "grow");
        panel.add(countdownLabel);
        panel.add(expiryProgressBar);
        panel.add(copyButton);
        return panel;
    }

    private JPanel createReplacementPanel() {
        JPanel panel = createSectionPanel("Request replacement");
        JLabel label = new JLabel("Placeholder or expression to replace");
        label.setLabelFor(matchExpressionField);
        panel.add(label);
        panel.add(matchExpressionField, "growx, wmin 0");
        JPanel optionsPanel = new JPanel(new MigLayout("insets 0"));
        optionsPanel.add(regexCheckBox);
        optionsPanel.add(bodyOnlyCheckBox);
        JButton previewRuleButton = new JButton("Test rule\u2026");
        previewRuleButton.addActionListener(event -> previewReplacementRule());
        optionsPanel.add(previewRuleButton);
        panel.add(optionsPanel);
        panel.add(
                new JLabel(
                        "Use {{TOTP}} in the request body for precise replacement. All matches are updated."));
        panel.add(
                new JLabel(
                        "Regex: name a capture group (?<otp>...) to replace only that value and keep its surrounding text."));
        return panel;
    }

    private JPanel createActionPanel() {
        JPanel panel = new JPanel(new MigLayout("fillx, insets 0, wrap 1", "[grow,fill]"));
        JPanel buttonPanel = new JPanel(new MigLayout("insets 0"));
        buttonPanel.add(startButton);
        buttonPanel.add(stopButton);
        JButton clearSecretButton = new JButton("Clear secret");
        clearSecretButton.addActionListener(event -> {
            session.stop();
            sharedSecretField.setText("");
            statusLabel.setText("Secret cleared. Requests are left unchanged.");
            refreshDisplay();
        });
        buttonPanel.add(clearSecretButton);
        panel.add(buttonPanel);
        panel.add(statusLabel);
        panel.add(requestCountLabel);
        panel.add(errorLabel);
        return panel;
    }

    private static JPanel createInstructionsPanel() {
        JPanel panel = createSectionPanel("Connect to a session handling rule");
        panel.add(
                new JLabel(
                        "1. Open Settings > Sessions > Session handling rules and add or edit a rule."));
        panel.add(
                new JLabel(
                        "2. Add \"Invoke a Burp extension\" and select the Google Authenticator action."));
        panel.add(
                new JLabel(
                        "3. Limit the rule's scope to the relevant login requests and tools. Verify updates in Logger."));
        return panel;
    }

    private void startSession() {
        if (disposed) {
            return;
        }
        session.stop();
        char[] sharedSecretCharacters = sharedSecretField.getPassword();
        try {
            periodSpinner.commitEdit();
            TotpGenerator generator =
                    TotpInputParser.parse(
                            new String(sharedSecretCharacters),
                            (TotpGenerator.Algorithm) algorithmComboBox.getSelectedItem(),
                            (Integer) codeLengthComboBox.getSelectedItem(),
                            ((Number) periodSpinner.getValue()).intValue());
            RequestReplacementRule replacementRule =
                    new RequestReplacementRule(
                            matchExpressionField.getText(),
                            regexCheckBox.isSelected(),
                            bodyOnlyCheckBox.isSelected());
            updatingForm = true;
            algorithmComboBox.setSelectedItem(generator.getAlgorithm());
            codeLengthComboBox.setSelectedItem(generator.getCodeLength());
            periodSpinner.setValue(generator.getPeriodSeconds());
            session.start(generator, replacementRule);
            statusLabel.setText("Running. Matching requests will receive a fresh code.");
        } catch (IllegalArgumentException | IllegalStateException e) {
            statusLabel.setText(e.getMessage());
        } catch (java.text.ParseException e) {
            statusLabel.setText("Enter a whole-number period between 1 and 300 seconds.");
        } finally {
            Arrays.fill(sharedSecretCharacters, '\0');
            updatingForm = false;
            refreshDisplay();
        }
    }

    private void pauseSessionForEdit() {
        if (updatingForm) {
            return;
        }
        session.stop();
        statusLabel.setText("Configuration changed. Apply & start to enable request updates.");
        refreshDisplay();
    }

    private void refreshDisplay() {
        var activeConfiguration = session.getActiveConfiguration();
        boolean sessionRunning = activeConfiguration != null;
        stopButton.setEnabled(sessionRunning);
        copyButton.setEnabled(sessionRunning);
        if (sessionRunning) {
            Instant currentTime = session.getCurrentTime();
            String code;
            try {
                code = activeConfiguration.generator().generateCode(currentTime);
            } catch (IllegalArgumentException | IllegalStateException e) {
                session.stop();
                statusLabel.setText(e.getMessage());
                refreshDisplay();
                return;
            }
            int codeMidpoint = code.length() / 2;
            codeLabel.setText(code.substring(0, codeMidpoint) + " " + code.substring(codeMidpoint));
            int secondsRemaining = activeConfiguration.generator().getSecondsRemaining(currentTime);
            countdownLabel.setText("Refreshes in " + secondsRemaining + "s");
            expiryProgressBar.setMaximum(activeConfiguration.generator().getPeriodSeconds());
            expiryProgressBar.setValue(secondsRemaining);
        } else {
            codeLabel.setText("------");
            countdownLabel.setText("Start to generate a code");
            expiryProgressBar.setValue(0);
        }
        requestCountLabel.setText(session.getUpdatedRequestCount() + " requests updated");
        String lastError = session.getLastError();
        errorLabel.setText(lastError == null ? " " : lastError);
        errorLabel.setToolTipText(lastError);
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
            statusLabel.setText(
                    "Code copied to the system clipboard. Request updates remain active.");
        } catch (IllegalStateException | java.awt.HeadlessException | SecurityException e) {
            statusLabel.setText("Clipboard unavailable. You can read the current code above.");
        }
    }

    private void previewReplacementRule() {
        JTextArea sampleTextArea = new JTextArea("{\"pin\":\"{{TOTP}}\"}", 5, 48);
        sampleTextArea.getAccessibleContext().setAccessibleName("Sample text to test");
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(
                new JLabel("Paste the text to match. Preview uses 123456 and sends no requests."),
                BorderLayout.NORTH);
        contentPanel.add(new JScrollPane(sampleTextArea), BorderLayout.CENTER);
        applyTheme.accept(contentPanel);
        if (JOptionPane.showConfirmDialog(
                        this,
                        contentPanel,
                        "Test replacement rule",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.PLAIN_MESSAGE)
                != JOptionPane.OK_OPTION) {
            return;
        }
        try {
            var replacementResult =
                    new RequestReplacementRule(
                                    matchExpressionField.getText(),
                                    regexCheckBox.isSelected(),
                                    bodyOnlyCheckBox.isSelected())
                            .replaceMatches(sampleTextArea.getText(), "123456");
            JTextArea previewTextArea = new JTextArea(replacementResult.text(), 6, 48);
            previewTextArea.setEditable(false);
            JScrollPane previewScrollPane = new JScrollPane(previewTextArea);
            applyTheme.accept(previewScrollPane);
            JOptionPane.showMessageDialog(
                    this,
                    previewScrollPane,
                    replacementResult.replacementCount() + " matches",
                    JOptionPane.PLAIN_MESSAGE);
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(
                    this, e.getMessage(), "Invalid rule", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void dispose() {
        disposed = true;
        refreshTimer.stop();
        session.stop();
        sharedSecretField.setText("");
        refreshDisplay();
    }

    private static JPanel createSectionPanel(String title) {
        JPanel panel = new JPanel(new MigLayout("fillx, wrap 1", "[grow,fill]"));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        return panel;
    }

    private static void addLabeledControl(
            JPanel panel, String text, javax.swing.JComponent component) {
        JLabel label = new JLabel(text);
        label.setLabelFor(component);
        panel.add(label);
        panel.add(component);
    }
}
