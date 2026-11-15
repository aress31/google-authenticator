package googleauthenticator.gui;

import googleauthenticator.otp.TotpGenerator;
import googleauthenticator.otp.TotpInputParser;
import googleauthenticator.session.AuthenticatorSession;
import googleauthenticator.session.RequestReplacementRule;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
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
import javax.swing.Scrollable;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** Native Swing controls inherit Burp's light/dark theme and keyboard behavior. */
public final class AuthenticatorPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient AuthenticatorSession session;
    private final JPasswordField sharedSecretField = new JPasswordField(28);
    private final JComboBox<TotpGenerator.Algorithm> algorithmComboBox = new JComboBox<>(TotpGenerator.Algorithm.values());
    private final JComboBox<Integer> codeLengthComboBox = new JComboBox<>(new Integer[] {6, 8});
    private final JSpinner periodSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 300, 1));
    private final JTextField matchExpressionField = new JTextField("{{TOTP}}", 28);
    private final JCheckBox regexCheckBox = new JCheckBox("Regular expression");
    private final JCheckBox bodyOnlyCheckBox = new JCheckBox("Request body only", true);
    private final JLabel codeLabel = new JLabel("------", SwingConstants.CENTER);
    private final JLabel countdownLabel = new JLabel("Start to generate a code", SwingConstants.CENTER);
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

    public AuthenticatorPanel(AuthenticatorSession session) {
        super(new BorderLayout());
        this.session = session;
        setName("authenticatorPanel");
        sharedSecretField.setName("sharedSecretField");
        matchExpressionField.setName("matchExpressionField");
        startButton.setName("startButton");
        stopButton.setName("stopButton");
        codeLabel.setName("codeLabel");
        statusLabel.setName("statusLabel");
        algorithmComboBox.setName("algorithmComboBox");
        codeLengthComboBox.setName("codeLengthComboBox");
        periodSpinner.setName("periodSpinner");
        ((JSpinner.DefaultEditor) periodSpinner.getEditor()).getTextField().setName("periodField");
        regexCheckBox.setName("regexCheckBox");
        bodyOnlyCheckBox.setName("bodyOnlyCheckBox");
        sharedSecretField.getAccessibleContext().setAccessibleName("Shared secret or TOTP provisioning URI");
        matchExpressionField.getAccessibleContext().setAccessibleName("Expression to replace");
        algorithmComboBox.getAccessibleContext().setAccessibleName("HMAC algorithm");
        codeLengthComboBox.getAccessibleContext().setAccessibleName("Code digits");
        periodSpinner.getAccessibleContext().setAccessibleName("Period in seconds");

        JPanel contentPanel = new ResponsiveContentPanel();
        contentPanel.setBorder(BorderFactory.createEmptyBorder(24, 28, 24, 28));
        GridBagConstraints layoutConstraints = new GridBagConstraints();
        layoutConstraints.gridx = 0;
        layoutConstraints.gridy = 0;
        layoutConstraints.gridwidth = 2;
        layoutConstraints.weightx = 1;
        layoutConstraints.fill = GridBagConstraints.HORIZONTAL;
        layoutConstraints.anchor = GridBagConstraints.NORTHWEST;
        layoutConstraints.insets = new Insets(0, 0, 20, 0);
        JPanel headingPanel = createVerticalPanel();
        headingPanel.add(createHeadingLabel("Google Authenticator", 24));
        headingPanel.add(Box.createVerticalStrut(6));
        headingPanel.add(new JLabel("Fresh one-time codes, applied through Burp session handling rules."));
        contentPanel.add(headingPanel, layoutConstraints);

        layoutConstraints.gridy++;
        layoutConstraints.gridwidth = 1;
        layoutConstraints.weightx = 0.68;
        layoutConstraints.insets = new Insets(0, 0, 20, 24);
        contentPanel.add(createAuthenticatorSettingsPanel(), layoutConstraints);
        layoutConstraints.gridx = 1;
        layoutConstraints.weightx = 0.32;
        layoutConstraints.insets = new Insets(0, 0, 20, 0);
        layoutConstraints.fill = GridBagConstraints.BOTH;
        contentPanel.add(createCodePanel(), layoutConstraints);

        layoutConstraints.gridx = 0;
        layoutConstraints.gridy++;
        layoutConstraints.gridwidth = 2;
        layoutConstraints.weightx = 1;
        layoutConstraints.fill = GridBagConstraints.HORIZONTAL;
        contentPanel.add(createReplacementPanel(), layoutConstraints);
        layoutConstraints.gridy++;
        contentPanel.add(createActionPanel(), layoutConstraints);
        layoutConstraints.gridy++;
        contentPanel.add(createInstructionsPanel(), layoutConstraints);
        layoutConstraints.gridy++;
        layoutConstraints.weighty = 1;
        contentPanel.add(new JPanel(), layoutConstraints);

        JScrollPane scroll = new JScrollPane(contentPanel);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);
        setPreferredSize(new Dimension(1000, 740));

        DocumentListener configurationChangeListener = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { pauseSessionForEdit(); }
            @Override public void removeUpdate(DocumentEvent event) { pauseSessionForEdit(); }
            @Override public void changedUpdate(DocumentEvent event) { pauseSessionForEdit(); }
        };
        sharedSecretField.getDocument().addDocumentListener(configurationChangeListener);
        matchExpressionField.getDocument().addDocumentListener(configurationChangeListener);
        ((JSpinner.DefaultEditor) periodSpinner.getEditor()).getTextField().getDocument().addDocumentListener(configurationChangeListener);
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
        JPanel panel = createVerticalPanel();
        panel.add(createHeadingLabel("Authenticator", 17));
        panel.add(Box.createVerticalStrut(14));
        JLabel label = new JLabel("Shared secret or otpauth://totp URI");
        label.setLabelFor(sharedSecretField);
        panel.add(label);
        panel.add(Box.createVerticalStrut(6));
        sharedSecretField.setMaximumSize(new Dimension(Integer.MAX_VALUE, sharedSecretField.getPreferredSize().height));
        sharedSecretField.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(sharedSecretField);
        panel.add(Box.createVerticalStrut(6));
        JCheckBox showSecretCheckBox = new JCheckBox("Show secret");
        char secretEchoCharacter = sharedSecretField.getEchoChar();
        showSecretCheckBox.addActionListener(event -> sharedSecretField.setEchoChar(showSecretCheckBox.isSelected() ? (char) 0 : secretEchoCharacter));
        panel.add(showSecretCheckBox);
        panel.add(Box.createVerticalStrut(12));
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
        addLabeledControl(optionsPanel, "Algorithm ", algorithmComboBox);
        optionsPanel.add(Box.createHorizontalStrut(14));
        addLabeledControl(optionsPanel, "Digits ", codeLengthComboBox);
        optionsPanel.add(Box.createHorizontalStrut(14));
        addLabeledControl(optionsPanel, "Period (s) ", periodSpinner);
        optionsPanel.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(optionsPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(new JLabel("A provisioning URI supplies its own algorithm, digits and period."));
        panel.add(Box.createVerticalStrut(6));
        panel.add(new JLabel("Secrets stay in memory and are never saved to settings or logs."));
        return panel;
    }

    private JPanel createCodePanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(getBorderColor()), BorderFactory.createEmptyBorder(16, 20, 16, 20)));
        panel.add(createHeadingLabel("Current code", 15), BorderLayout.NORTH);
        codeLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 40));
        codeLabel.getAccessibleContext().setAccessibleName("Current one-time code");
        panel.add(codeLabel, BorderLayout.CENTER);
        JPanel footerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints layoutConstraints = new GridBagConstraints();
        layoutConstraints.gridx = 0;
        layoutConstraints.gridy = 0;
        layoutConstraints.fill = GridBagConstraints.HORIZONTAL;
        layoutConstraints.weightx = 1;
        footerPanel.add(countdownLabel, layoutConstraints);
        layoutConstraints.gridy++;
        layoutConstraints.insets = new Insets(10, 0, 10, 0);
        expiryProgressBar.setPreferredSize(new Dimension(190, 5));
        footerPanel.add(expiryProgressBar, layoutConstraints);
        layoutConstraints.gridy++;
        layoutConstraints.insets = new Insets(0, 0, 0, 0);
        footerPanel.add(copyButton, layoutConstraints);
        panel.add(footerPanel, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createReplacementPanel() {
        JPanel panel = createVerticalPanel();
        panel.add(createHeadingLabel("Request replacement", 17));
        panel.add(Box.createVerticalStrut(12));
        JLabel label = new JLabel("Placeholder or expression to replace");
        label.setLabelFor(matchExpressionField);
        panel.add(label);
        panel.add(Box.createVerticalStrut(6));
        matchExpressionField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        matchExpressionField.setMaximumSize(new Dimension(Integer.MAX_VALUE, matchExpressionField.getPreferredSize().height));
        matchExpressionField.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(matchExpressionField);
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 8));
        optionsPanel.add(regexCheckBox);
        optionsPanel.add(Box.createHorizontalStrut(20));
        optionsPanel.add(bodyOnlyCheckBox);
        optionsPanel.add(Box.createHorizontalStrut(20));
        JButton previewRuleButton = new JButton("Test rule\u2026");
        previewRuleButton.addActionListener(event -> previewReplacementRule());
        optionsPanel.add(previewRuleButton);
        optionsPanel.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(optionsPanel);
        panel.add(new JLabel("Use {{TOTP}} in the request body for precise replacement. All matches are updated."));
        panel.add(Box.createVerticalStrut(5));
        panel.add(new JLabel("Regex: name a capture group (?<otp>...) to replace only that value and keep its surrounding text."));
        return panel;
    }

    private JPanel createActionPanel() {
        JPanel panel = createVerticalPanel();
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
        startButton.setFont(startButton.getFont().deriveFont(Font.BOLD));
        buttonPanel.add(startButton);
        buttonPanel.add(Box.createHorizontalStrut(8));
        buttonPanel.add(stopButton);
        buttonPanel.add(Box.createHorizontalStrut(8));
        JButton clearSecretButton = new JButton("Clear secret");
        clearSecretButton.setName("clearSecretButton");
        clearSecretButton.addActionListener(event -> {
            session.stop();
            sharedSecretField.setText("");
            statusLabel.setText("Secret cleared. Requests are left unchanged.");
            refreshDisplay();
        });
        buttonPanel.add(clearSecretButton);
        buttonPanel.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(buttonPanel);
        panel.add(Box.createVerticalStrut(12));
        panel.add(statusLabel);
        panel.add(Box.createVerticalStrut(6));
        panel.add(requestCountLabel);
        panel.add(Box.createVerticalStrut(6));
        panel.add(errorLabel);
        return panel;
    }

    private static JPanel createInstructionsPanel() {
        JPanel panel = createVerticalPanel();
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, getBorderColor()),
                BorderFactory.createEmptyBorder(18, 0, 0, 0)));
        panel.add(createHeadingLabel("Connect to a session handling rule", 15));
        panel.add(Box.createVerticalStrut(8));
        panel.add(new JLabel("1. Open Settings > Sessions > Session handling rules and add or edit a rule."));
        panel.add(Box.createVerticalStrut(5));
        panel.add(new JLabel("2. Add \"Invoke a Burp extension\" and select the Google Authenticator action."));
        panel.add(Box.createVerticalStrut(5));
        panel.add(new JLabel("3. Limit the rule's scope to the relevant login requests and tools. Verify updates in Logger."));
        return panel;
    }

    private void startSession() {
        if (disposed) { return; }
        session.stop();
        char[] sharedSecretCharacters = sharedSecretField.getPassword();
        try {
            periodSpinner.commitEdit();
            TotpGenerator generator = TotpInputParser.parse(new String(sharedSecretCharacters),
                    (TotpGenerator.Algorithm) algorithmComboBox.getSelectedItem(),
                    (Integer) codeLengthComboBox.getSelectedItem(), ((Number) periodSpinner.getValue()).intValue());
            RequestReplacementRule replacementRule = new RequestReplacementRule(
                    matchExpressionField.getText(), regexCheckBox.isSelected(), bodyOnlyCheckBox.isSelected());
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
        if (updatingForm) { return; }
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
        errorLabel.setText(session.getLastError() == null ? " " : session.getLastError());
        errorLabel.setToolTipText(session.getLastError());
    }

    private void copyCurrentCode() {
        var activeConfiguration = session.getActiveConfiguration();
        if (activeConfiguration == null) { return; }
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new StringSelection(activeConfiguration.generator().generateCode(session.getCurrentTime())), null);
            statusLabel.setText("Code copied to the system clipboard. Request updates remain active.");
        } catch (IllegalStateException | java.awt.HeadlessException | SecurityException e) {
            statusLabel.setText("Clipboard unavailable. You can read the current code above.");
        }
    }

    private void previewReplacementRule() {
        JTextArea sampleTextArea = new JTextArea("{\"pin\":\"{{TOTP}}\"}", 5, 48);
        sampleTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        sampleTextArea.getAccessibleContext().setAccessibleName("Sample text to test");
        JPanel contentPanel = new JPanel(new BorderLayout(0, 8));
        contentPanel.add(new JLabel("Paste the text to match. Preview uses 123456 and sends no requests."), BorderLayout.NORTH);
        contentPanel.add(new JScrollPane(sampleTextArea), BorderLayout.CENTER);
        if (JOptionPane.showConfirmDialog(this, contentPanel, "Test replacement rule",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) { return; }
        try {
            var replacementResult = new RequestReplacementRule(matchExpressionField.getText(), regexCheckBox.isSelected(), bodyOnlyCheckBox.isSelected())
                    .replaceMatches(sampleTextArea.getText(), "123456");
            JTextArea previewTextArea = new JTextArea(replacementResult.text(), 6, 48);
            previewTextArea.setEditable(false);
            previewTextArea.setFont(sampleTextArea.getFont());
            JOptionPane.showMessageDialog(this, new JScrollPane(previewTextArea), replacementResult.replacementCount() + " matches",
                    JOptionPane.PLAIN_MESSAGE);
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Invalid rule", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void dispose() {
        disposed = true;
        refreshTimer.stop();
        session.stop();
        sharedSecretField.setText("");
        refreshDisplay();
    }

    private static JPanel createVerticalPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(LEFT_ALIGNMENT);
        return panel;
    }

    private static JLabel createHeadingLabel(String text, int size) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, size));
        label.setAlignmentX(LEFT_ALIGNMENT);
        return label;
    }

    private static void addLabeledControl(JPanel panel, String text, javax.swing.JComponent component) {
        JLabel label = new JLabel(text);
        label.setLabelFor(component);
        panel.add(label);
        panel.add(component);
    }

    private static Color getBorderColor() {
        Color color = UIManager.getColor("Separator.foreground");
        return color == null ? Color.GRAY : color;
    }

    /** Stack the code panel below the inputs when the Burp tab is narrow. */
    private static final class ResponsiveContentPanel extends JPanel implements Scrollable {
        private static final long serialVersionUID = 1L;
        private final transient Map<Component, GridBagConstraints> wideLayoutConstraints = new LinkedHashMap<>();
        private boolean compactLayout;
        private boolean layoutInitialized;

        ResponsiveContentPanel() { super(new GridBagLayout()); }

        @Override
        public void doLayout() {
            updateLayoutConstraints();
            super.doLayout();
        }

        @Override
        public Dimension getPreferredSize() {
            updateLayoutConstraints();
            return super.getPreferredSize();
        }

        private void updateLayoutConstraints() {
            GridBagLayout layout = (GridBagLayout) getLayout();
            if (!layoutInitialized) {
                for (Component child : getComponents()) {
                    wideLayoutConstraints.put(child, layout.getConstraints(child));
                }
            }
            int availableWidth = getParent() == null ? getWidth() : getParent().getWidth();
            boolean useCompactLayout = availableWidth < 900;
            if (!layoutInitialized || useCompactLayout != compactLayout) {
                wideLayoutConstraints.forEach((child, wideConstraints) -> {
                    GridBagConstraints componentConstraints = (GridBagConstraints) wideConstraints.clone();
                    if (useCompactLayout && wideConstraints.gridy == 1) {
                        componentConstraints.gridx = 0;
                        componentConstraints.gridwidth = 2;
                        componentConstraints.weightx = 1;
                        componentConstraints.insets = new Insets(0, 0, 20, 0);
                        if (wideConstraints.gridx == 1) { componentConstraints.gridy = 2; }
                    } else if (useCompactLayout && wideConstraints.gridy >= 2) {
                        componentConstraints.gridy++;
                    }
                    layout.setConstraints(child, componentConstraints);
                });
                compactLayout = useCompactLayout;
                layoutInitialized = true;
            }
        }

        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return visible.height - 16; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
