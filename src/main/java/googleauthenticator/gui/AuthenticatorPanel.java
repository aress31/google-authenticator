package googleauthenticator.gui;

import googleauthenticator.otp.Provisioning;
import googleauthenticator.otp.Totp;
import googleauthenticator.session.MatchRule;
import googleauthenticator.session.SessionState;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Component;
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
import javax.swing.Scrollable;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** Native Swing controls inherit Burp's light/dark theme and keyboard behavior. */
public final class AuthenticatorPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient SessionState state;
    private final JPasswordField secret = new JPasswordField(28);
    private final JComboBox<Totp.Algorithm> algorithm = new JComboBox<>(Totp.Algorithm.values());
    private final JComboBox<Integer> digits = new JComboBox<>(new Integer[] {6, 8});
    private final JSpinner period = new JSpinner(new SpinnerNumberModel(30, 1, 300, 1));
    private final JTextField expression = new JTextField("{{TOTP}}", 28);
    private final JCheckBox regex = new JCheckBox("Regular expression");
    private final JCheckBox bodyOnly = new JCheckBox("Request body only", true);
    private final JLabel code = new JLabel("------", SwingConstants.CENTER);
    private final JLabel countdown = new JLabel("Start to generate a code", SwingConstants.CENTER);
    private final JProgressBar progress = new JProgressBar(0, 30);
    private final JLabel status = new JLabel("Paused. Add your shared secret to get started.");
    private final JLabel activity = new JLabel("0 requests updated");
    private final JLabel issue = new JLabel(" ");
    private final JButton start = new JButton("Apply & start");
    private final JButton stop = new JButton("Stop");
    private final JButton copy = new JButton("Copy code");
    private final Timer timer;
    private boolean updating;
    private boolean disposed;

    public AuthenticatorPanel(SessionState state) {
        super(new BorderLayout());
        this.state = state;
        setName("authenticatorPanel");
        secret.setName("secret");
        expression.setName("expression");
        start.setName("start");
        stop.setName("stop");
        code.setName("code");
        status.setName("status");
        algorithm.setName("algorithm");
        digits.setName("digits");
        period.setName("period");
        ((JSpinner.DefaultEditor) period.getEditor()).getTextField().setName("periodInput");
        regex.setName("regex");
        bodyOnly.setName("bodyOnly");
        secret.getAccessibleContext().setAccessibleName("Shared secret or TOTP provisioning URI");
        expression.getAccessibleContext().setAccessibleName("Expression to replace");
        algorithm.getAccessibleContext().setAccessibleName("HMAC algorithm");
        digits.getAccessibleContext().setAccessibleName("Code digits");
        period.getAccessibleContext().setAccessibleName("Period in seconds");

        JPanel content = new ResponsiveContent();
        content.setBorder(BorderFactory.createEmptyBorder(24, 28, 24, 28));
        GridBagConstraints cell = new GridBagConstraints();
        cell.gridx = 0;
        cell.gridy = 0;
        cell.gridwidth = 2;
        cell.weightx = 1;
        cell.fill = GridBagConstraints.HORIZONTAL;
        cell.anchor = GridBagConstraints.NORTHWEST;
        cell.insets = new Insets(0, 0, 20, 0);
        JPanel heading = vertical();
        heading.add(title("Google Authenticator", 24));
        heading.add(Box.createVerticalStrut(6));
        heading.add(new JLabel("Fresh one-time codes, applied through Burp session handling rules."));
        content.add(heading, cell);

        cell.gridy++;
        cell.gridwidth = 1;
        cell.weightx = 0.68;
        cell.insets = new Insets(0, 0, 20, 24);
        content.add(credentials(), cell);
        cell.gridx = 1;
        cell.weightx = 0.32;
        cell.insets = new Insets(0, 0, 20, 0);
        cell.fill = GridBagConstraints.BOTH;
        content.add(codePanel(), cell);

        cell.gridx = 0;
        cell.gridy++;
        cell.gridwidth = 2;
        cell.weightx = 1;
        cell.fill = GridBagConstraints.HORIZONTAL;
        content.add(rulePanel(), cell);
        cell.gridy++;
        content.add(controls(), cell);
        cell.gridy++;
        content.add(instructions(), cell);
        cell.gridy++;
        cell.weighty = 1;
        content.add(new JPanel(), cell);

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);
        setPreferredSize(new Dimension(1000, 740));

        DocumentListener changed = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { pauseForEdit(); }
            @Override public void removeUpdate(DocumentEvent event) { pauseForEdit(); }
            @Override public void changedUpdate(DocumentEvent event) { pauseForEdit(); }
        };
        secret.getDocument().addDocumentListener(changed);
        expression.getDocument().addDocumentListener(changed);
        ((JSpinner.DefaultEditor) period.getEditor()).getTextField().getDocument().addDocumentListener(changed);
        algorithm.addActionListener(event -> pauseForEdit());
        digits.addActionListener(event -> pauseForEdit());
        period.addChangeListener(event -> pauseForEdit());
        regex.addActionListener(event -> pauseForEdit());
        bodyOnly.addActionListener(event -> pauseForEdit());
        start.addActionListener(event -> start());
        secret.addActionListener(event -> start());
        stop.addActionListener(event -> {
            state.stop();
            status.setText("Paused. Requests are left unchanged.");
            refresh();
        });
        copy.addActionListener(event -> copyCode());
        timer = new Timer(250, event -> refresh());
        timer.start();
        refresh();
    }

    private JPanel credentials() {
        JPanel panel = vertical();
        panel.add(title("Authenticator", 17));
        panel.add(Box.createVerticalStrut(14));
        JLabel label = new JLabel("Shared secret or otpauth://totp URI");
        label.setLabelFor(secret);
        panel.add(label);
        panel.add(Box.createVerticalStrut(6));
        secret.setMaximumSize(new Dimension(Integer.MAX_VALUE, secret.getPreferredSize().height));
        secret.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(secret);
        panel.add(Box.createVerticalStrut(6));
        JCheckBox reveal = new JCheckBox("Show secret");
        char echo = secret.getEchoChar();
        reveal.addActionListener(event -> secret.setEchoChar(reveal.isSelected() ? (char) 0 : echo));
        panel.add(reveal);
        panel.add(Box.createVerticalStrut(12));
        JPanel options = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
        labeled(options, "Algorithm ", algorithm);
        options.add(Box.createHorizontalStrut(14));
        labeled(options, "Digits ", digits);
        options.add(Box.createHorizontalStrut(14));
        labeled(options, "Period (s) ", period);
        options.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(options);
        panel.add(Box.createVerticalStrut(10));
        panel.add(new JLabel("A provisioning URI supplies its own algorithm, digits and period."));
        panel.add(Box.createVerticalStrut(6));
        panel.add(new JLabel("Secrets stay in memory and are never saved to settings or logs."));
        return panel;
    }

    private JPanel codePanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(borderColor()), BorderFactory.createEmptyBorder(16, 20, 16, 20)));
        panel.add(title("Current code", 15), BorderLayout.NORTH);
        code.setFont(new Font(Font.MONOSPACED, Font.BOLD, 40));
        code.getAccessibleContext().setAccessibleName("Current one-time code");
        panel.add(code, BorderLayout.CENTER);
        JPanel footer = new JPanel(new GridBagLayout());
        GridBagConstraints cell = new GridBagConstraints();
        cell.gridx = 0;
        cell.gridy = 0;
        cell.fill = GridBagConstraints.HORIZONTAL;
        cell.weightx = 1;
        footer.add(countdown, cell);
        cell.gridy++;
        cell.insets = new Insets(10, 0, 10, 0);
        progress.setPreferredSize(new Dimension(190, 5));
        footer.add(progress, cell);
        cell.gridy++;
        cell.insets = new Insets(0, 0, 0, 0);
        footer.add(copy, cell);
        panel.add(footer, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel rulePanel() {
        JPanel panel = vertical();
        panel.add(title("Request replacement", 17));
        panel.add(Box.createVerticalStrut(12));
        JLabel label = new JLabel("Placeholder or expression to replace");
        label.setLabelFor(expression);
        panel.add(label);
        panel.add(Box.createVerticalStrut(6));
        expression.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        expression.setMaximumSize(new Dimension(Integer.MAX_VALUE, expression.getPreferredSize().height));
        expression.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(expression);
        JPanel options = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 8));
        options.add(regex);
        options.add(Box.createHorizontalStrut(20));
        options.add(bodyOnly);
        options.add(Box.createHorizontalStrut(20));
        JButton test = new JButton("Test rule\u2026");
        test.addActionListener(event -> testRule());
        options.add(test);
        options.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(options);
        panel.add(new JLabel("Use {{TOTP}} in the request body for precise replacement. All matches are updated."));
        panel.add(Box.createVerticalStrut(5));
        panel.add(new JLabel("Regex: name a capture group (?<otp>...) to replace only that value and keep its surrounding text."));
        return panel;
    }

    private JPanel controls() {
        JPanel panel = vertical();
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
        start.setFont(start.getFont().deriveFont(Font.BOLD));
        buttons.add(start);
        buttons.add(Box.createHorizontalStrut(8));
        buttons.add(stop);
        buttons.add(Box.createHorizontalStrut(8));
        JButton clear = new JButton("Clear secret");
        clear.setName("clear");
        clear.addActionListener(event -> {
            state.stop();
            secret.setText("");
            status.setText("Secret cleared. Requests are left unchanged.");
            refresh();
        });
        buttons.add(clear);
        buttons.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(buttons);
        panel.add(Box.createVerticalStrut(12));
        panel.add(status);
        panel.add(Box.createVerticalStrut(6));
        panel.add(activity);
        panel.add(Box.createVerticalStrut(6));
        panel.add(issue);
        return panel;
    }

    private static JPanel instructions() {
        JPanel panel = vertical();
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, borderColor()),
                BorderFactory.createEmptyBorder(18, 0, 0, 0)));
        panel.add(title("Connect to a session handling rule", 15));
        panel.add(Box.createVerticalStrut(8));
        panel.add(new JLabel("1. Open Settings > Sessions > Session handling rules and add or edit a rule."));
        panel.add(Box.createVerticalStrut(5));
        panel.add(new JLabel("2. Add \"Invoke a Burp extension\" and select the Google Authenticator action."));
        panel.add(Box.createVerticalStrut(5));
        panel.add(new JLabel("3. Limit the rule's scope to the relevant login requests and tools. Verify updates in Logger."));
        return panel;
    }

    private void start() {
        if (disposed) { return; }
        state.stop();
        char[] password = secret.getPassword();
        try {
            period.commitEdit();
            Totp totp = Provisioning.parse(new String(password), (Totp.Algorithm) algorithm.getSelectedItem(),
                    (Integer) digits.getSelectedItem(), ((Number) period.getValue()).intValue());
            MatchRule rule = new MatchRule(expression.getText(), regex.isSelected(), bodyOnly.isSelected());
            updating = true;
            algorithm.setSelectedItem(totp.algorithm());
            digits.setSelectedItem(totp.digits());
            period.setValue(totp.period());
            state.start(totp, rule);
            status.setText("Running. Matching requests will receive a fresh code.");
        } catch (IllegalArgumentException | IllegalStateException e) {
            status.setText(e.getMessage());
        } catch (java.text.ParseException e) {
            status.setText("Enter a whole-number period between 1 and 300 seconds.");
        } finally {
            Arrays.fill(password, '\0');
            updating = false;
            refresh();
        }
    }

    private void pauseForEdit() {
        if (updating) { return; }
        state.stop();
        status.setText("Configuration changed. Apply & start to enable request updates.");
        refresh();
    }

    private void refresh() {
        var configuration = state.configuration();
        boolean running = configuration != null;
        stop.setEnabled(running);
        copy.setEnabled(running);
        if (running) {
            Instant now = state.now();
            String token;
            try {
                token = configuration.totp().codeAt(now);
            } catch (IllegalArgumentException | IllegalStateException e) {
                state.stop();
                status.setText(e.getMessage());
                refresh();
                return;
            }
            int half = token.length() / 2;
            code.setText(token.substring(0, half) + " " + token.substring(half));
            int remaining = configuration.totp().secondsRemaining(now);
            countdown.setText("Refreshes in " + remaining + "s");
            progress.setMaximum(configuration.totp().period());
            progress.setValue(remaining);
        } else {
            code.setText("------");
            countdown.setText("Start to generate a code");
            progress.setValue(0);
        }
        activity.setText(state.updatedRequests() + " requests updated");
        issue.setText(state.lastIssue() == null ? " " : state.lastIssue());
        issue.setToolTipText(state.lastIssue());
    }

    private void copyCode() {
        var configuration = state.configuration();
        if (configuration == null) { return; }
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new StringSelection(configuration.totp().codeAt(state.now())), null);
            status.setText("Code copied to the system clipboard. Request updates remain active.");
        } catch (IllegalStateException | java.awt.HeadlessException | SecurityException e) {
            status.setText("Clipboard unavailable. You can read the current code above.");
        }
    }

    private void testRule() {
        JTextArea sample = new JTextArea("{\"pin\":\"{{TOTP}}\"}", 5, 48);
        sample.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        sample.getAccessibleContext().setAccessibleName("Sample text to test");
        JPanel content = new JPanel(new BorderLayout(0, 8));
        content.add(new JLabel("Paste the text to match. Preview uses 123456 and sends no requests."), BorderLayout.NORTH);
        content.add(new JScrollPane(sample), BorderLayout.CENTER);
        if (JOptionPane.showConfirmDialog(this, content, "Test replacement rule",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) { return; }
        try {
            var replacement = new MatchRule(expression.getText(), regex.isSelected(), bodyOnly.isSelected())
                    .replace(sample.getText(), "123456");
            JTextArea output = new JTextArea(replacement.value(), 6, 48);
            output.setEditable(false);
            output.setFont(sample.getFont());
            JOptionPane.showMessageDialog(this, new JScrollPane(output), replacement.matches() + " matches",
                    JOptionPane.PLAIN_MESSAGE);
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Invalid rule", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void dispose() {
        disposed = true;
        timer.stop();
        state.stop();
        secret.setText("");
        refresh();
    }

    private static JPanel vertical() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(LEFT_ALIGNMENT);
        return panel;
    }

    private static JLabel title(String text, int size) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, size));
        label.setAlignmentX(LEFT_ALIGNMENT);
        return label;
    }

    private static void labeled(JPanel panel, String text, javax.swing.JComponent component) {
        JLabel label = new JLabel(text);
        label.setLabelFor(component);
        panel.add(label);
        panel.add(component);
    }

    private static Color borderColor() {
        Color color = UIManager.getColor("Separator.foreground");
        return color == null ? Color.GRAY : color;
    }

    /** Stack the code panel below the inputs when the Burp tab is narrow. */
    private static final class ResponsiveContent extends JPanel implements Scrollable {
        private static final long serialVersionUID = 1L;
        private final transient Map<Component, GridBagConstraints> original = new LinkedHashMap<>();
        private boolean compact;
        private boolean initialized;

        ResponsiveContent() { super(new GridBagLayout()); }

        @Override
        public void doLayout() {
            configureLayout();
            super.doLayout();
        }

        @Override
        public Dimension getPreferredSize() {
            configureLayout();
            return super.getPreferredSize();
        }

        private void configureLayout() {
            GridBagLayout grid = (GridBagLayout) getLayout();
            if (!initialized) {
                for (Component child : getComponents()) {
                    original.put(child, grid.getConstraints(child));
                }
            }
            int available = getParent() == null ? getWidth() : getParent().getWidth();
            boolean narrow = available < 900;
            if (!initialized || narrow != compact) {
                original.forEach((child, wide) -> {
                    GridBagConstraints constraints = (GridBagConstraints) wide.clone();
                    if (narrow && wide.gridy == 1) {
                        constraints.gridx = 0;
                        constraints.gridwidth = 2;
                        constraints.weightx = 1;
                        constraints.insets = new Insets(0, 0, 20, 0);
                        if (wide.gridx == 1) { constraints.gridy = 2; }
                    } else if (narrow && wide.gridy >= 2) {
                        constraints.gridy++;
                    }
                    grid.setConstraints(child, constraints);
                });
                compact = narrow;
                initialized = true;
            }
        }

        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return visible.height - 16; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
