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

/** Owns form controls and validation, notifying the parent when the user edits or submits. */
final class ConfigurationPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final String LITERAL_HINT =
            "Enter the placeholder used in your request, such as {{TOTP}}. Every match is replaced.";

    private final transient Runnable configurationChanged;

    private final JPasswordField sharedSecretField = new JPasswordField(28);
    private final JComboBox<TotpGenerator.Algorithm> algorithmComboBox =
            new JComboBox<>(TotpGenerator.Algorithm.values());
    private final JComboBox<Integer> codeLengthComboBox = new JComboBox<>(new Integer[] {6, 8});
    private final JSpinner periodSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 300, 1));

    private final JTextField matchExpressionField = new JTextField("{{TOTP}}", 28);
    private final JCheckBox regexCheckBox = new JCheckBox("Regular expression");
    private final JCheckBox bodyOnlyCheckBox = new JCheckBox("Request body only", true);
    private final JTextArea replacementHint = createHint(LITERAL_HINT);

    private boolean updatingForm;

    ConfigurationPanel(
            Runnable configurationChanged,
            Runnable applyConfiguration,
            Component dialogParent,
            Consumer<Component> applyTheme) {
        // One grid keeps labels and fields aligned across both sections.
        super(new MigLayout("fillx, insets 0, gap 12 16", "[label][grow,fill]"));
        this.configurationChanged = configurationChanged;
        configureControls();
        addAuthenticatorSettings();
        add(new JSeparator(), "span, growx, wrap 24");
        addReplacementSettings(dialogParent, applyTheme);
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
        periodSpinner.setToolTipText("Code lifetime in seconds (1-300).");
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
        var editListener = new DocumentChangeListener(this::notifyConfigurationChanged);
        sharedSecretField.getDocument().addDocumentListener(editListener);
        matchExpressionField.getDocument().addDocumentListener(editListener);
        ((JSpinner.DefaultEditor) periodSpinner.getEditor())
                .getTextField()
                .getDocument()
                .addDocumentListener(editListener);
        algorithmComboBox.addActionListener(event -> notifyConfigurationChanged());
        codeLengthComboBox.addActionListener(event -> notifyConfigurationChanged());
        periodSpinner.addChangeListener(event -> notifyConfigurationChanged());
        regexCheckBox.addActionListener(event -> {
            replacementHint.setText(
                    regexCheckBox.isSelected()
                            ? "Every regex match is replaced. Use a named group (?<otp>...) to replace only that group."
                            : LITERAL_HINT);
            notifyConfigurationChanged();
        });
        bodyOnlyCheckBox.addActionListener(event -> notifyConfigurationChanged());
        sharedSecretField.addActionListener(event -> applyConfiguration.run());
    }

    private void notifyConfigurationChanged() {
        if (!updatingForm) {
            configurationChanged.run();
        }
    }

    private void addAuthenticatorSettings() {
        add(createHeading("Authenticator"), "span, wrap 6");
        add(
                createHint(
                        "Supports Google Authenticator and other RFC 6238-compatible TOTP apps."),
                "span, growx, wmin 0, wrap 16");
        add(createLabel("Shared secret:", sharedSecretField));
        add(sharedSecretField, "growx, wmin 0, hmin 32, wrap 6");
        add(
                createHint(
                        "Provisioning URI settings override the options below when you click Apply & start."),
                "skip 1, growx, wmin 0, wrap 16");
        add(createLabel("Algorithm:", algorithmComboBox));
        JPanel optionsPanel =
                new JPanel(
                        new MigLayout(
                                "insets 0, gapx 12",
                                "[130:pref,fill]24[][80:pref,fill]24[][90:pref,fill][]",
                                "[32:pref,fill]"));
        optionsPanel.add(algorithmComboBox);
        optionsPanel.add(createLabel("Digits:", codeLengthComboBox));
        optionsPanel.add(codeLengthComboBox);
        optionsPanel.add(createLabel("Period:", periodSpinner));
        optionsPanel.add(periodSpinner);
        optionsPanel.add(new JLabel("s"));
        add(optionsPanel, "growx, wrap 24");
    }

    private void addReplacementSettings(Component dialogParent, Consumer<Component> applyTheme) {
        add(createHeading("Request replacement"), "span, wrap 16");
        add(createLabel("Text to replace:", matchExpressionField));
        add(matchExpressionField, "growx, wmin 0, hmin 32, wrap 6");
        add(replacementHint, "skip 1, growx, wmin 0, wrap 16");
        add(regexCheckBox, "span, split 3, growx 0");
        add(bodyOnlyCheckBox, "growx 0, gapleft 16");
        JButton previewRuleButton = new JButton("Test rule");
        previewRuleButton.putClientProperty(
                "FlatLaf.style",
                "background: $Panel.background; foreground: $Label.foreground; borderColor: $Component.borderColor");
        previewRuleButton.addActionListener(event ->
                RulePreviewDialog.show(dialogParent, this::readReplacementRule, applyTheme));
        add(previewRuleButton, "growx 0, gapleft push, wmin 130, hmin 34");
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
        // Read-only guidance should align with its grid cell, without text-field padding.
        hint.putClientProperty(
                "FlatLaf.style",
                "font: $Label.font; foreground: $Label.disabledForeground; border: 0,0,0,0; margin: 0,0,0,0");

        return hint;
    }
}
