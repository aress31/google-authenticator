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

package burp;

import googleauthenticator.gui.Tab;
import googleauthenticator.utils.DataSet;

public class BurpExtender implements IBurpExtender {

  public static final boolean DEBUG = Boolean.FALSE;

  // Time in ms between the pin updates - usually around 30s
  // Arbitrary set to 500ms in order to minimise synchronisation errors
  public static final int DELAY = 500;

  public static final String COPYRIGHT = "Copyright \u00a9 2016 - 2021 Alexandre Teyar, Aegis Cyber (www.aegiscyber.co.uk). All Rights Reserved.";
  public static final String EXTENSION = "Google Authenticator";

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    DataSet dataSet = new DataSet(callbacks);
    Tab tab = new Tab(callbacks, dataSet);

    callbacks.setExtensionName(EXTENSION);

    callbacks.addSuiteTab(tab);
    callbacks.printOutput(String.format("'%s' initialised", EXTENSION));

    callbacks.registerSessionHandlingAction(new SessionHandlingAction(callbacks, dataSet));
  }
}
