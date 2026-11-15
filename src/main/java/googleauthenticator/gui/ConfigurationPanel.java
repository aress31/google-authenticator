package googleauthenticator.gui;

import googleauthenticator.otp.TotpGenerator;
import googleauthenticator.otp.TotpInputParser;
import googleauthenticator.session.RequestReplacementRule;

import net.miginfocom.swing.MigLayout;

import java.awt.Component;
import java.text.ParseException;
import java.util.Arrays;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** Owns form controls and validation, notifying the parent when the user edits or submits. */
final class ConfigurationPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient Runnable configurationChanged;
    private final JPasswordField sharedSecretField = new JPasswordField(28);
    private final JComboBox<TotpGenerator.Algorithm> algorithmComboBox =
            new JComboBox<>(TotpGenerator.Algorithm.values());
    private final JComboBox<Integer> codeLengthComboBox = new JComboBox<>(new Integer[] {6, 8});
    private final JSpinner periodSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 300, 1));
    private final JTextField matchExpressionField = new JTextField("{{TOTP}}", 28);
    private final JCheckBox regexCheckBox = new JCheckBox("Regular expression");
    private final JCheckBox bodyOnlyCheckBox = new JCheckBox("Request body only", true);

    private boolean updatingForm;

    ConfigurationPanel(
            Runnable configurationChanged,
            Runnable applyConfiguration,
            Consumer<Component> applyTheme) {
        // One grid keeps labels and fields aligned across both sections.
        super(new MigLayout("fillx, insets 0, gap 12 16", "[label][grow,fill]"));
        this.configurationChanged = configurationChanged;
        configureControls();
        addAuthenticatorSettings();
        add(new JSeparator(), "span, growx, wrap 24");
        addReplacementSettings(applyTheme);
        registerListeners(applyConfiguration);
    }

    TotpGenerator readGenerator() throws ParseException {
        char[] secret = sharedSecretField.getPassword();
        try {
            periodSpinner.commitEdit();

            return TotpInputParser.parse(
                    new String(secret),
                    (TotpGenerator.Algorithm) algorithmComboBox.getSelectedItem(),
                    (Integer) codeLengthComboBox.getSelectedItem(),
                    ((Number) periodSpinner.getValue()).intValue());
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    RequestReplacementRule readReplacementRule() {
        return new RequestReplacementRule(
                matchExpressionField.getText(),
                regexCheckBox.isSelected(),
                bodyOnlyCheckBox.isSelected());
    }

    void showGeneratorOptions(TotpGenerator generator) {
        updatingForm = true;
        try {
            algorithmComboBox.setSelectedItem(generator.getAlgorithm());
            codeLengthComboBox.setSelectedItem(generator.getCodeLength());
            periodSpinner.setValue(generator.getPeriodSeconds());
        } finally {
            updatingForm = false;
        }
    }

    void clearSecret() {
        sharedSecretField.setText("");
    }

    private void configureControls() {
        sharedSecretField
                .getAccessibleContext()
                .setAccessibleName("Shared secret or TOTP provisioning URI");
        matchExpressionField.getAccessibleContext().setAccessibleName("Expression to replace");
        algorithmComboBox.getAccessibleContext().setAccessibleName("HMAC algorithm");
        codeLengthComboBox.getAccessibleContext().setAccessibleName("Code digits");
        periodSpinner.getAccessibleContext().setAccessibleName("Period in seconds");
        sharedSecretField.putClientProperty("FlatLaf.style", "showRevealButton: true");
        sharedSecretField.putClientProperty(
                "JTextField.placeholderText", "Base32 shared secret or otpauth://totp URI");
        sharedSecretField.setToolTipText(
                "Secrets stay in memory and are not saved to settings or logs.");
        algorithmComboBox.setToolTipText(
                "A provisioning URI supplies its own algorithm, digits and period.");
        matchExpressionField.setToolTipText(
                "All matches are replaced. In regex mode, use (?<otp>...) to replace only that group.");
        bodyOnlyCheckBox.setToolTipText(
                "Uncheck to also match text in the request headers and URL.");
    }

    private void registerListeners(Runnable applyConfiguration) {
        DocumentListener editListener =
                new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent event) {
                        notifyConfigurationChanged();
                    }

                    @Override
                    public void removeUpdate(DocumentEvent event) {
                        notifyConfigurationChanged();
                    }

                    @Override
                    public void changedUpdate(DocumentEvent event) {
                        notifyConfigurationChanged();
                    }
                };
        sharedSecretField.getDocument().addDocumentListener(editListener);
        matchExpressionField.getDocument().addDocumentListener(editListener);
        ((JSpinner.DefaultEditor) periodSpinner.getEditor())
                .getTextField()
                .getDocument()
                .addDocumentListener(editListener);
        algorithmComboBox.addActionListener(event -> notifyConfigurationChanged());
        codeLengthComboBox.addActionListener(event -> notifyConfigurationChanged());
        periodSpinner.addChangeListener(event -> notifyConfigurationChanged());
        regexCheckBox.addActionListener(event -> notifyConfigurationChanged());
        bodyOnlyCheckBox.addActionListener(event -> notifyConfigurationChanged());
        sharedSecretField.addActionListener(event -> applyConfiguration.run());
    }

    private void notifyConfigurationChanged() {
        if (!updatingForm) {
            configurationChanged.run();
        }
    }

    private void addAuthenticatorSettings() {
        add(createHeading("Authenticator"), "span, wrap 16");
        add(createLabel("Shared secret:", sharedSecretField));
        add(sharedSecretField, "growx, wmin 0, hmin 32, wrap 6");
        add(
                createHint(
                        "Enter a Base32 secret or an otpauth://totp URI. A URI supplies the algorithm, digits and period."),
                "skip 1, growx, wmin 0, wrap 16");
        add(createLabel("Algorithm:", algorithmComboBox));
        JPanel optionsPanel =
                new JPanel(
                        new MigLayout(
                                "insets 0, gapx 12",
                                "[130:pref,fill]24[][80:pref,fill]24[][90:pref,fill][]"));
        optionsPanel.add(algorithmComboBox, "hmin 32");
        optionsPanel.add(createLabel("Digits:", codeLengthComboBox));
        optionsPanel.add(codeLengthComboBox, "hmin 32");
        optionsPanel.add(createLabel("Period:", periodSpinner));
        optionsPanel.add(periodSpinner, "hmin 32");
        optionsPanel.add(new JLabel("s"));
        add(optionsPanel, "growx, wrap 24");
    }

    private void addReplacementSettings(Consumer<Component> applyTheme) {
        add(createHeading("Request replacement"), "span, wrap 16");
        add(createLabel("Placeholder:", matchExpressionField));
        add(matchExpressionField, "growx, wmin 0, hmin 32, wrap 6");
        add(
                createHint(
                        "Put {{TOTP}} in your request, or enable Regular expression to match an existing value. All matches are replaced."),
                "skip 1, growx, wmin 0, wrap 16");
        JPanel optionsPanel = new JPanel(new MigLayout("fillx, insets 0", "[]16[][grow][]"));
        optionsPanel.add(regexCheckBox);
        optionsPanel.add(bodyOnlyCheckBox);
        JButton previewRuleButton = new JButton("Test rule");
        previewRuleButton.addActionListener(
                event -> RulePreviewDialog.show(this, this::readReplacementRule, applyTheme));
        optionsPanel.add(previewRuleButton, "skip 1, wmin 130, hmin 34");
        add(optionsPanel, "span, growx, wrap");
    }

    private static JLabel createHeading(String title) {
        JLabel heading = new JLabel(title);
        heading.putClientProperty("FlatLaf.style", "font: bold +6");

        return heading;
    }

    private static JLabel createLabel(String text, JComponent component) {
        JLabel label = new JLabel(text);
        label.setLabelFor(component);

        return label;
    }

    private static JTextArea createHint(String text) {
        JTextArea hint = new JTextArea(text);
        hint.setEditable(false);
        hint.setFocusable(false);
        hint.setLineWrap(true);
        hint.setWrapStyleWord(true);
        hint.setOpaque(false);
        hint.putClientProperty(
                "FlatLaf.style", "font: $Label.font; foreground: $Label.disabledForeground");

        return hint;
    }
}
