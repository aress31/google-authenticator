package googleauthenticator.gui;

import googleauthenticator.session.RequestReplacementRule;

import net.miginfocom.swing.MigLayout;

import java.awt.Component;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/** Shows a local, live replacement preview without changing the active session. */
final class RulePreviewDialog {
    private final Supplier<RequestReplacementRule> ruleSupplier;
    private final JTextArea sampleTextArea = new JTextArea("{\"pin\":\"{{TOTP}}\"}", 5, 48);
    private final JTextArea previewTextArea = new JTextArea(5, 48);
    private final JLabel matchCountLabel = new JLabel();
    private final JButton closeButton = UiComponents.secondaryButton("Close");

    private RulePreviewDialog(Supplier<RequestReplacementRule> ruleSupplier) {
        this.ruleSupplier = ruleSupplier;
        sampleTextArea.getAccessibleContext().setAccessibleName("Sample text to test");
        previewTextArea.setEditable(false);
        previewTextArea.getAccessibleContext().setAccessibleName("Replacement result");
        sampleTextArea
                .getDocument()
                .addDocumentListener(new DocumentChangeListener(this::updatePreview));
    }

    static void show(
            Component parent,
            Supplier<RequestReplacementRule> ruleSupplier,
            Consumer<Component> applyTheme) {
        RulePreviewDialog preview = new RulePreviewDialog(ruleSupplier);
        JPanel contentPanel = preview.createContentPanel();
        applyTheme.accept(contentPanel);
        preview.updatePreview();
        JOptionPane optionPane =
                new JOptionPane(
                        contentPanel,
                        JOptionPane.PLAIN_MESSAGE,
                        JOptionPane.DEFAULT_OPTION,
                        null,
                        new Object[0]);
        JDialog dialog = optionPane.createDialog(parent, "Test replacement rule");
        preview.closeButton.addActionListener(event -> dialog.dispose());
        dialog.getRootPane().setDefaultButton(preview.closeButton);
        try {
            dialog.setVisible(true);
        } finally {
            dialog.dispose();
        }
    }

    private JPanel createContentPanel() {
        JPanel contentPanel =
                new JPanel(
                        new MigLayout(
                                "fill, insets 0, wrap 1, gapy 12",
                                "[grow,fill]",
                                "[][][grow,fill][][grow,fill][]"));
        contentPanel.add(
                new JLabel("Updates as you type using sample code 123456. No requests are sent."));
        contentPanel.add(UiComponents.labelFor("Sample text", sampleTextArea));
        contentPanel.add(new JScrollPane(sampleTextArea), "grow");
        contentPanel.add(UiComponents.labelFor("Result", previewTextArea));
        contentPanel.add(new JScrollPane(previewTextArea), "grow");
        JPanel actionPanel = new JPanel(new MigLayout("fillx, insets 0", "[grow,fill][]"));
        actionPanel.add(matchCountLabel);
        actionPanel.add(closeButton, "hmin 34");
        contentPanel.add(actionPanel);

        return contentPanel;
    }

    private void updatePreview() {
        try {
            var replacementResult =
                    ruleSupplier.get().replaceMatches(sampleTextArea.getText(), "123456");
            previewTextArea.setText(replacementResult.text());
            int matchCount = replacementResult.replacementCount();
            matchCountLabel.setText(
                    matchCount == 0
                            ? "No matches. Result unchanged."
                            : matchCount + (matchCount == 1 ? " match" : " matches"));
        } catch (IllegalArgumentException e) {
            previewTextArea.setText(e.getMessage());
            matchCountLabel.setText("Invalid rule");
        }
        previewTextArea.setCaretPosition(0);
    }
}
