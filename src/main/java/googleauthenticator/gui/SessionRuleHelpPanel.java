package googleauthenticator.gui;

import net.miginfocom.swing.MigLayout;

import java.awt.Font;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;

/** Collapsible instructions for connecting the extension to a Burp session rule. */
final class SessionRuleHelpPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    SessionRuleHelpPanel() {
        super(new MigLayout("fillx, insets 0, wrap 1, hidemode 3", "[grow,fill]"));
        JButton toggle = new JButton("\u25b6  Session rule setup help");
        toggle.setHorizontalAlignment(SwingConstants.LEFT);
        // The logical font includes fallback glyphs for the expand/collapse arrows.
        toggle.setFont(new Font(Font.DIALOG, Font.BOLD, toggle.getFont().getSize()));
        JTextArea instructions =
                new JTextArea(
                        "1. Open Settings > Sessions > Session handling rules and add or edit a rule.\n\n"
                                + "2. Add \"Invoke a Burp extension\" and select the Google Authenticator action.\n\n"
                                + "3. Limit the rule's scope to the relevant requests and tools. Verify updates in Logger.");
        instructions.setFont(toggle.getFont().deriveFont(Font.PLAIN));
        instructions.setEditable(false);
        instructions.setOpaque(false);
        instructions.setLineWrap(true);
        instructions.setWrapStyleWord(true);
        instructions.setVisible(false);
        toggle.addActionListener(event -> {
            boolean expanded = !instructions.isVisible();
            instructions.setVisible(expanded);
            toggle.setText((expanded ? "\u25bc" : "\u25b6") + "  Session rule setup help");
            revalidate();
            repaint();
        });
        add(toggle, "hmin 34");
        add(instructions, "growx, wmin 0, gaptop 10");
    }
}
