package googleauthenticator.gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.UIManager;

/** Collapsible instructions for connecting the extension to a Burp session rule. */
final class SessionRuleHelpPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    SessionRuleHelpPanel() {
        super(new MigLayout("fillx, insets 0, wrap 1, gapy 12, hidemode 3", "[grow,fill]"));
        JButton toggle = new JButton("Session rule setup help");
        toggle.setHorizontalAlignment(SwingConstants.LEFT);
        toggle.setIcon(UIManager.getIcon("Tree.collapsedIcon"));
        JTextArea instructions =
                new JTextArea(
                        "1. Open Settings > Sessions > Session handling rules and add or edit a rule.\n\n"
                                + "2. Add \"Invoke a Burp extension\" and select the Google Authenticator action.\n\n"
                                + "3. Limit the rule's scope to the relevant requests and tools. Verify updates in Logger.\n\n"
                                + "If codes are rejected, check that your system clock is synchronized.");
        instructions.setEditable(false);
        instructions.setOpaque(false);
        instructions.setLineWrap(true);
        instructions.setWrapStyleWord(true);
        instructions.putClientProperty(
                "FlatLaf.style", "font: $Label.font; border: 0,0,0,0; margin: 0,0,0,0");
        instructions.setVisible(false);
        toggle.addActionListener(event -> {
            boolean expanded = !instructions.isVisible();
            instructions.setVisible(expanded);
            toggle.setIcon(
                    UIManager.getIcon(expanded ? "Tree.expandedIcon" : "Tree.collapsedIcon"));
            revalidate();
            repaint();
        });
        add(toggle, "hmin 34");
        add(instructions, "growx, wmin 0");
    }
}
