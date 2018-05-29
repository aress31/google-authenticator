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

package burp;

import burp.ui.Tab;
import plugin.DataSet;

public class BurpExtender implements IBurpExtender {

  public static Boolean DEBUG = Boolean.TRUE;

  // time is ms between pin code updates - normal time is 30s
  public static int DELAY = 5 * 1000;

  public static String COPYRIGHT = "Copyright \u00a9 2018 Alexandre Teyar All Rights Reserved";
  public static String EXTENSION = "Google Authenticator";

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    DataSet dataSet = new DataSet();
    SessionHandlingAction sessionHandlingAction = new SessionHandlingAction(callbacks,
        dataSet);
    Tab tab = new Tab(callbacks, dataSet);

    callbacks.setExtensionName(EXTENSION);
    callbacks.addSuiteTab(tab);
    callbacks.printOutput(String.format("%s tab created", EXTENSION));

    callbacks.registerSessionHandlingAction(sessionHandlingAction);

    if (DEBUG) {
      callbacks.printOutput(String.format("%s", sessionHandlingAction));
      callbacks.printOutput(String.format("%s", tab));
      callbacks.printOutput(String.format("%s", dataSet));
    }
  }
}
