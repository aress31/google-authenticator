/*
#    Copyright (C) 2018 - 2021 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.
*/

package googleauthenticator.gui;

import static burp.BurpExtender.COPYRIGHT;
import static burp.BurpExtender.DEBUG;
import static burp.BurpExtender.DELAY;
import static burp.BurpExtender.EXTENSION;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.SessionHandlingAction;
import googleauthenticator.utils.DataSet;

public class Tab extends JPanel implements ITab {

  private transient DataSet dataSet;
  private transient IBurpExtenderCallbacks callbacks;
  private transient Timer timer;

  private JLabel pinLabel = new JLabel();
  private JTextField keyTextField = new JTextField(null, 64);

  public Tab(IBurpExtenderCallbacks callbacks, DataSet dataSet) {
    this.dataSet = dataSet;
    this.callbacks = callbacks;

    initComponents();
    initTimer();
  }

  private void initTimer() {
    this.timer = new Timer(DELAY, e -> {
      this.dataSet.setPin(this.dataSet.getKey());
      this.pinLabel.setText(this.dataSet.getPin());

      if (DEBUG) {
        this.callbacks.printOutput(String.format("%s",
            ((SessionHandlingAction) this.callbacks.getSessionHandlingActions().get(0)).getDataSet().toString()));
      }
    });

    this.timer.setRepeats(Boolean.TRUE);
    this.timer.setInitialDelay(0);
  }

  private void initComponents() {
    this.setLayout(new BorderLayout());

    JPanel keyPanel = initKeyPanel();

    JPanel configurationPanel = initConfigurationPanel();
    JPanel twoFAPanel = initTwoFAPanel();

    JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    splitPane.setTopComponent(configurationPanel);
    splitPane.setBottomComponent(twoFAPanel);

    JPanel southPanel = new JPanel();
    southPanel.add(new JLabel(COPYRIGHT));

    this.add(keyPanel, BorderLayout.NORTH);
    this.add(splitPane);
    this.add(southPanel, BorderLayout.SOUTH);
  }

  private JPanel initKeyPanel() {
    this.keyTextField.setHorizontalAlignment(SwingConstants.CENTER);

    JButton runButton = new JButton("Run/Update");
    runButton.setBackground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.burpOrange"));
    runButton.setFont(new Font(runButton.getFont().getName(), Font.BOLD, runButton.getFont().getSize()));
    runButton.setForeground(javax.swing.UIManager.getLookAndFeelDefaults().getColor("Burp.primaryButtonForeground"));
    runButton.addActionListener(e -> {
      // TODO: Check if 'key' is valid, if not, print 'statusLabel' in Color.RED and
      // do nothing/stop timer.
      this.dataSet.setKey(keyTextField.getText());

      if (this.dataSet.getKey() == null) {
        this.pinLabel.setText(null);
        this.timer.stop();
      } else {
        this.timer.restart();
      }

      if (DEBUG) {
        this.callbacks.printOutput(String.format("%s",
            ((SessionHandlingAction) this.callbacks.getSessionHandlingActions().get(0)).getDataSet().toString()));
      }
    });

    JPanel keyPanel = new JPanel();
    keyPanel.setBorder(BorderFactory.createTitledBorder(""));
    keyPanel.add(new JLabel("Shared secret:"));
    keyPanel.add(this.keyTextField);
    keyPanel.add(runButton);

    return keyPanel;
  }

  private JPanel initConfigurationPanel() {
    JPanel configurationPanel = new JPanel(new GridBagLayout());
    configurationPanel.setBorder(BorderFactory.createTitledBorder("Session Handling Rule Configuration"));

    JLabel instructionsLabel = new JLabel("<html>" + "<body style=\"text-align: justify; text-justify: inter-word;\">"
        + "<p>Follow the instructions below to properly configure " + EXTENSION
        + " in order to be more eaily assess application(s) relying on Google 2FA services.</p>" + "<ol>"
        + "<li>Specify the expression to match in the field below (accepts regex).</li>"
        + "<li>Configure a session handling rule under <b>'Project Options -> Sessions -> Session Handing Rules'</b> that invokes <b>"
        + EXTENSION + "</b>," + "<br/>"
        + "see https://portswigger.net/support/configuring-burp-suites-session-handling-rules for detailed information on how to configure Burp's session handling rules.</li>"
        + "<li>Monitor issued request(s) using either the <b>'Open session tracer'</b> feature available under <b>'Project Options -> Sessions -> Session Handing Rules'</b> or the"
        + "<br/>" + "<b>'Logger'</b> to make sure that Google 2FA codes are getting updated.</li>" + "</ol>"
        + "<em>Note: Issued request(s) will be searched for the configured (regular) expression which will then get automatically replaced with refreshed/valid Google 2FA codes.</em>"
        + "</html>");
    instructionsLabel.putClientProperty("html.disable", null);

    JTextField regexTextField = new JTextField(32);
    regexTextField.getDocument().addDocumentListener(new DocumentListener() {
      void update() {
        dataSet.setRegex(regexTextField.getText());

        if (DEBUG) {
          callbacks.printOutput(String.format("%s",
              ((SessionHandlingAction) callbacks.getSessionHandlingActions().get(0)).getDataSet().toString()));
        }
      }

      @Override
      public void insertUpdate(DocumentEvent e) {
        update();
      }

      @Override
      public void removeUpdate(DocumentEvent e) {
        update();
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
        update();
      }
    });
    // Prevents JTextField from collapsing on resizes...
    regexTextField.setMinimumSize(new Dimension(regexTextField.getPreferredSize()));

    JCheckBox hasRegexCheckbox = new JCheckBox("regex");
    hasRegexCheckbox.addActionListener(e -> {
      AbstractButton abstractButton = (AbstractButton) e.getSource();
      dataSet.setHasRegex(abstractButton.isSelected());

      if (DEBUG) {
        this.callbacks.printOutput(String.format("%s",
            ((SessionHandlingAction) this.callbacks.getSessionHandlingActions().get(0)).getDataSet().toString()));
      }
    });

    JPanel regexPanel = new JPanel();
    regexPanel.add(new JLabel("Expression to match:"));
    regexPanel.add(regexTextField);
    regexPanel.add(hasRegexCheckbox);

    GridBagConstraints gridBagConstraints = new GridBagConstraints();
    gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
    gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
    gridBagConstraints.insets = new Insets(4, 8, 4, 8);
    gridBagConstraints.gridy = 0;
    gridBagConstraints.weightx = 1.0;
    gridBagConstraints.weighty = 0;

    configurationPanel.add(instructionsLabel, gridBagConstraints);

    gridBagConstraints.gridy = 1;
    gridBagConstraints.fill = GridBagConstraints.NONE;
    gridBagConstraints.weightx = 0;
    gridBagConstraints.weighty = 1.0;

    configurationPanel.add(regexPanel, gridBagConstraints);

    return configurationPanel;
  }

  private JPanel initTwoFAPanel() {
    JPanel twoFAPanel = new JPanel();
    twoFAPanel.setBorder(BorderFactory.createTitledBorder("Google 2FA Code"));

    // Default size is: 11
    this.pinLabel
        .setFont(new Font(this.pinLabel.getFont().getName(), Font.BOLD, this.pinLabel.getFont().getSize() + 37));

    twoFAPanel.add(this.pinLabel);

    return twoFAPanel;
  }

  @Override
  public String getTabCaption() {
    return EXTENSION;
  }

  @Override
  public Component getUiComponent() {
    return this;
  }
}
