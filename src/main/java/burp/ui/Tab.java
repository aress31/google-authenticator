/*
#    Copyright (C) 2018 Alexandre Teyar

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

package burp.ui;

import static burp.BurpExtender.COPYRIGHT;
import static burp.BurpExtender.DEBUG;
import static burp.BurpExtender.DELAY;
import static burp.BurpExtender.EXTENSION;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.SessionHandlingAction;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.Timer;
import javax.swing.border.TitledBorder;
import plugin.DataSet;
import plugin.SimpleDocumentListener;

public class Tab implements ITab {

  private IBurpExtenderCallbacks callbacks;
  private DataSet dataSet;

  private JLabel pinLabel;

  private JPanel rootPanel;
  private JPanel keyPanel;
  private JPanel configurationPanel;
  private JPanel twoFAPanel;

  private Font keyFont = new Font(null, Font.PLAIN, 11);
  private Font borderFont = new Font(null, Font.ITALIC, 14);
  private Font instructionFont = new Font(null, Font.BOLD, 12);
  private Font pinFont = new Font(null, Font.BOLD, 48);
  private Font noteFont = new Font(null, Font.ITALIC, 11);

  public Tab(IBurpExtenderCallbacks callbacks, DataSet dataSet) {
    this.callbacks = callbacks;
    this.dataSet = dataSet;

    initialiseUI();
    initialiseTimer();
  }

  private void initialiseUI() {
    this.rootPanel = new JPanel();

    this.rootPanel.setLayout(new BoxLayout(this.rootPanel, BoxLayout.PAGE_AXIS));

    this.keyPanel = new JPanel();

    this.configurationPanel = new JPanel();
    this.configurationPanel.setBorder(BorderFactory
        .createTitledBorder(null, "Session Handling Rule Configuration",
            TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, this.borderFont, null));
    this.configurationPanel.setPreferredSize(new Dimension(480, 240));

    this.twoFAPanel = new JPanel();
    this.twoFAPanel.setBorder(BorderFactory
        .createTitledBorder(null, "Google 2FA Code",
            TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, this.borderFont, null));
    this.twoFAPanel.setPreferredSize(new Dimension(480, 120));

    JPanel copyrightPanel = new JPanel();
    copyrightPanel.add(new JLabel(COPYRIGHT));

    this.rootPanel.add(this.keyPanel);
    this.rootPanel.add(this.configurationPanel);
    this.rootPanel.add(this.twoFAPanel);
    this.rootPanel.add(copyrightPanel);

    this.rootPanel.revalidate();
    this.rootPanel.repaint();

    drawKeyPanel();
    drawConfigurationPanel();
    drawTwoFAPanel();
  }

  private void initialiseTimer() {
    Timer timer = new Timer(DELAY, e -> {
      this.dataSet.setPin(this.dataSet.getKey());
      this.pinLabel.setText(this.dataSet.getPin());

      if (DEBUG) {
        callbacks.printOutput(String.format("%s",
            ((SessionHandlingAction) this.callbacks.getSessionHandlingActions().get(0)).getDataSet()
                .toString()));
      }
    });
    timer.setInitialDelay(0);
    timer.setRepeats(Boolean.TRUE);
    timer.start();
  }

  private void drawKeyPanel() {
    this.keyPanel.setLayout(new GridBagLayout());
    GridBagConstraints gridBagConstraints = new GridBagConstraints();

    JLabel keyLabel = new JLabel("Shared secret:");
    keyLabel.setFont(this.keyFont);

    JTextField keyTextField = new JTextField(48);
    keyTextField.setHorizontalAlignment(JTextField.CENTER);
    keyLabel.setLabelFor(keyTextField);
    keyTextField.getDocument().addDocumentListener((SimpleDocumentListener) e -> {
      this.dataSet.setKey(keyTextField.getText());
      this.dataSet.setPin(keyTextField.getText());
      this.pinLabel.setText(this.dataSet.getPin());

      if (DEBUG) {
        this.callbacks.printOutput(String.format("%s",
            ((SessionHandlingAction) this.callbacks.getSessionHandlingActions().get(0))
                .getDataSet().toString()));
      }
    });

    this.keyPanel.add(keyLabel, gridBagConstraints);

    gridBagConstraints.insets = new Insets(0, 10, 0, 0);
    this.keyPanel.add(keyTextField, gridBagConstraints);

    this.keyPanel.revalidate();
    this.keyPanel.repaint();
  }

  private void drawConfigurationPanel() {
    this.configurationPanel.setLayout(new GridBagLayout());
    GridBagConstraints gridBagConstraints = new GridBagConstraints();

    JLabel instructionLabel = new JLabel("1/ Find match(es) to the expression below:");
    instructionLabel.setFont(this.instructionFont);
    JLabel instructionLabel1 = new JLabel(
        "2/ Set up a session handling rule that invokes this Burp extension");
    instructionLabel1.setFont(this.instructionFont);
    JLabel instructionLabel2 = new JLabel(
        "3/ Monitor changes to issued request(s) using the 'Open session tracer' feature");
    instructionLabel2.setFont(this.instructionFont);
    JLabel instructionLabel3 = new JLabel(
        "Note: Issued request(s) will be searched for the regular expression which will then get replaced with the Google 2FA code");
    instructionLabel3.setFont(this.noteFont);

    JTextField regexTextField = new JTextField(32);
    regexTextField.getDocument().addDocumentListener(
        (SimpleDocumentListener) e -> {
          this.dataSet.setRegex(regexTextField.getText());

          if (DEBUG) {
            this.callbacks.printOutput(String.format("%s",
                ((SessionHandlingAction) this.callbacks.getSessionHandlingActions().get(0))
                    .getDataSet().toString()));
          }
        });

    JCheckBox hasRegexCheckbox = new JCheckBox("regex");
    hasRegexCheckbox.addActionListener(e -> {
      AbstractButton abstractButton = (AbstractButton) e.getSource();
      this.dataSet.setHasRegex(abstractButton.isSelected());

      if (DEBUG) {
        this.callbacks.printOutput(String.format("%s",
            ((SessionHandlingAction) this.callbacks.getSessionHandlingActions().get(0))
                .getDataSet().toString()));
      }
    });

    JPanel regexPanel = new JPanel();
    regexPanel.add(regexTextField);
    regexPanel.add(hasRegexCheckbox);

    gridBagConstraints.anchor = GridBagConstraints.FIRST_LINE_START;
    gridBagConstraints.fill = GridBagConstraints.NONE;
    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 0;
    gridBagConstraints.weightx = 1.0;
    gridBagConstraints.weighty = 1.0;
    this.configurationPanel.add(instructionLabel, gridBagConstraints);

    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 1;
    this.configurationPanel.add(regexPanel, gridBagConstraints);

    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 2;
    this.configurationPanel.add(instructionLabel1, gridBagConstraints);

    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 3;
    this.configurationPanel.add(instructionLabel2, gridBagConstraints);

    gridBagConstraints.gridx = 0;
    gridBagConstraints.gridy = 4;
    this.configurationPanel.add(instructionLabel3, gridBagConstraints);

    this.configurationPanel.revalidate();
    this.configurationPanel.repaint();
  }

  private void drawTwoFAPanel() {
    this.twoFAPanel.setLayout(new GridBagLayout());

    this.pinLabel = new JLabel();
    this.pinLabel.setFont(this.pinFont);

    this.twoFAPanel.add(pinLabel);

    this.twoFAPanel.revalidate();
    this.twoFAPanel.repaint();
  }

  @Override
  public Component getUiComponent() {
    return rootPanel;
  }

  @Override
  public String getTabCaption() {
    return EXTENSION;
  }
}
