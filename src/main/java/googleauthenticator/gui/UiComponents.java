package googleauthenticator.gui;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTextArea;

/** Shared presentation defaults for the extension's standard controls. */
final class UiComponents {
    private static final String TEXT_STYLE = "font: $Label.font; border: 0,0,0,0; margin: 0,0,0,0";

    private UiComponents() {}

    static JButton secondaryButton(String text) {
        JButton button = new JButton(text);
        button.putClientProperty(
                "FlatLaf.style",
                "background: $Panel.background; foreground: $Label.foreground; borderColor: $Component.borderColor");

        return button;
    }

    static JLabel heading(String text) {
        JLabel label = new JLabel(text);
        label.putClientProperty("FlatLaf.style", "font: bold +6");

        return label;
    }

    static JLabel labelFor(String text, JComponent component) {
        JLabel label = new JLabel(text);
        label.setLabelFor(component);

        return label;
    }

    static JTextArea text(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        // Read-only text aligns with its grid cell, without text-field padding.
        area.putClientProperty("FlatLaf.style", TEXT_STYLE);

        return area;
    }

    static JTextArea hint(String text) {
        JTextArea area = text(text);
        area.putClientProperty(
                "FlatLaf.style", TEXT_STYLE + "; foreground: $Label.disabledForeground");

        return area;
    }
}
