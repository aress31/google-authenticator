package googleauthenticator.utils;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import burp.IBurpExtenderCallbacks;

public final class DataSet {

  private IBurpExtenderCallbacks callbacks;

  private boolean hasRegex = Boolean.FALSE;
  private String key;
  private String pin;
  private String regex;
  private String prefix;
  private String suffix;

  public DataSet(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  public boolean getHasRegex() {
    return hasRegex;
  }

  public String getKey() {
    return key;
  }

  public String getPinWithPrefixAndSuffix() {
    if(this.pin == null)
      return null;

    String pin = this.prefix == null ? "" : this.prefix;
    pin += this.pin;
    pin += this.suffix == null ? "" : this.suffix;

    return pin;
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
      int _pin = new GoogleAuthenticator().getTotpPassword(key);
      this.pin = String.format("%06d", _pin);
    } else {
      this.pin = null;
    }
  }

  public void setRegex(String regex) {
    this.regex = regex;
  }

  public void setPrefix(String prefix) {
    this.prefix = prefix;
  }

  public void setSuffix(String suffix) {
    this.suffix = suffix;
  }

  @Override
  public String toString() {
    return "DataSet{" +
        "callbacks=" + callbacks +
        ", hasRegex=" + hasRegex +
        ", key='" + key + '\'' +
        ", pin='" + pin + '\'' +
        ", regex='" + regex + '\'' +
        ", prefix='" + prefix + '\'' +
        ", suffix='" + suffix + '\'' +
        '}';
  }
}
