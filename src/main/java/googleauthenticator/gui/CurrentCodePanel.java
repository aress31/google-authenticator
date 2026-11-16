package googleauthenticator.gui;

import googleauthenticator.otp.TotpGenerator;

import net.miginfocom.swing.MigLayout;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.time.Instant;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JSeparator;
import javax.swing.UIManager;

/** Displays the current code and session status; session changes belong to the parent panel. */
final class CurrentCodePanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final JLabel codeLabel = new JLabel("--- ---");
    // A space preserves the countdown row's height while paused.
    private final JLabel countdownLabel = new JLabel(" ");
    private final JProgressBar expiryProgressBar = new JProgressBar(0, 30);
    private final JButton copyButton = new JButton("Copy code");

    private final JLabel stateIndicator = new JLabel("\u25a0");
    private final JLabel stateLabel = new JLabel("Paused");
    private final JLabel requestCountLabel = new JLabel("0 requests updated");

    CurrentCodePanel(Runnable copyCode) {
        super(new MigLayout("fillx, insets 24, wrap 1, gapy 0", "[grow,fill]"));
        JLabel heading = new JLabel("Current code");
        heading.putClientProperty("FlatLaf.style", "font: bold +6");
        add(heading, "wrap 16");
        codeLabel.getAccessibleContext().setAccessibleName("Current one-time code");
        add(codeLabel, "w pref!, wrap 12");
        add(countdownLabel, "wrap 8");
        expiryProgressBar.setBorderPainted(false);
        add(expiryProgressBar, "h 8!, growx, wrap 16");
        copyButton.putClientProperty(
                "FlatLaf.style",
                "background: $Panel.background; foreground: $Label.foreground; borderColor: $Component.borderColor");
        copyButton.addActionListener(event -> copyCode.run());
        add(copyButton, "growx 0, wmin 150, hmin 34, wrap 24");
        add(new JSeparator(), "growx, wrap 24");
        JPanel statePanel = new JPanel(new MigLayout("fillx, insets 0, gap 8", "[][grow,fill]"));
        statePanel.add(stateIndicator);
        statePanel.add(stateLabel, "wrap");
        statePanel.add(requestCountLabel, "span, growx");
        add(statePanel);
    }

    /** Called after Burp applies its theme so sizing uses the user's current font. */
    void configureAppearance() {
        Font baseFont = countdownLabel.getFont();
        codeLabel.setFont(
                new Font(Font.MONOSPACED, Font.BOLD, Math.round(baseFont.getSize2D() * 4.5f)));
        var codeMetrics = codeLabel.getFontMetrics(codeLabel.getFont());
        // Reserve eight digits so changing codes never changes the sidebar's width.
        codeLabel.setPreferredSize(
                new Dimension(codeMetrics.stringWidth("0000 0000"), codeMetrics.getHeight()));
        stateLabel.putClientProperty("FlatLaf.style", "font: bold +2");
        stateIndicator.setFont(stateLabel.getFont());
    }

    void showCode(TotpGenerator generator, Instant currentTime, long updatedRequestCount) {
        String code = generator.generateCode(currentTime);
        int secondsRemaining = generator.getSecondsRemaining(currentTime);
        int codeMidpoint = code.length() / 2;
        codeLabel.setText(code.substring(0, codeMidpoint) + " " + code.substring(codeMidpoint));
        countdownLabel.setText("Refreshes in " + secondsRemaining + " s");
        expiryProgressBar.setMaximum(generator.getPeriodSeconds());
        expiryProgressBar.setValue(secondsRemaining);
        showState(true, updatedRequestCount);
    }

    void showPaused(long updatedRequestCount) {
        codeLabel.setText("--- ---");
        countdownLabel.setText(" ");
        expiryProgressBar.setValue(0);
        showState(false, updatedRequestCount);
    }

    private void showState(boolean running, long updatedRequestCount) {
        stateLabel.setText(running ? "Running" : "Paused");
        stateIndicator.setForeground(
                running ? new Color(0x009900) : UIManager.getColor("Label.disabledForeground"));
        copyButton.setEnabled(running);
        requestCountLabel.setText(updatedRequestCount + " requests updated");
    }
}
