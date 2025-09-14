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

import static burp.BurpExtender.DEBUG;
import static burp.BurpExtender.EXTENSION;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import googleauthenticator.utils.DataSet;

public class SessionHandlingAction implements ISessionHandlingAction {

  private IBurpExtenderCallbacks callbacks;
  private DataSet dataSet;

  SessionHandlingAction(IBurpExtenderCallbacks callbacks, DataSet dataSet) {
    this.callbacks = callbacks;
    this.dataSet = dataSet;
  }

  public DataSet getDataSet() {
    return dataSet;
  }

  @Override
  public String getActionName() {
    return String.format("%s: 2FA code applied to selected parameter", EXTENSION);
  }

  @Override
  public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
    if (this.dataSet.getPinWithPrefixAndSuffix() != null && this.dataSet.getRegex() != null) {
      String request = this.callbacks.getHelpers().bytesToString(currentRequest.getRequest());

      if (DEBUG) {
        this.callbacks.printOutput("original request");
        this.callbacks.printOutput(String.format("%s", request));
      }

      if (this.dataSet.getHasRegex()) {
        Pattern pattern = Pattern.compile(this.dataSet.getRegex());
        Matcher matcher = pattern.matcher(request);

        if (matcher.find()) {
          request = matcher.replaceAll(this.dataSet.getPinWithPrefixAndSuffix());
        }
      } else {
        request = request.replaceAll(this.dataSet.getRegex(), this.dataSet.getPinWithPrefixAndSuffix());
      }

      if (DEBUG) {
        this.callbacks.printOutput("edited request");
        this.callbacks.printOutput(String.format("%s", request));
      }

      currentRequest.setRequest(this.callbacks.getHelpers().stringToBytes(request));
    }
  }
}
