package googleauthenticator.utils;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import burp.IBurpExtenderCallbacks;

public final class DataSet {

  private IBurpExtenderCallbacks callbacks;

  private boolean hasRegex = Boolean.FALSE;
  private String key;
  private String pin;
  private String regex;

  public DataSet(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  public boolean getHasRegex() {
    return hasRegex;
  }

  public String getKey() {
    return key;
  }

  public String getPin() {
    return pin;
  }

  public String getRegex() {
    return regex;
  }

  public void setHasRegex(Boolean hasRegex) {
    this.hasRegex = hasRegex;
  }

  public void setKey(String key) {
    if (key != null && !key.equals("")) {
      this.key = key;
    } else {
      this.key = null;
    }
  }

  public void setPin(String key) {
    if (key != null && !key.equals("")) {
      this.pin = Integer.toString(new GoogleAuthenticator().getTotpPassword(key));
    } else {
      this.pin = null;
    }
  }

  public void setRegex(String regex) {
    this.regex = regex;
  }

  public String toString() {
    return "DataSet{" + "hasRegex=" + hasRegex + ", key='" + key + '\'' + ", pin='" + pin + '\'' + ", regex='" + regex
        + '\'' + '}';
  }
}
