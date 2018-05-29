package plugin;

import com.warrenstrange.googleauth.GoogleAuthenticator;

public class DataSet {

  private Boolean hasRegex = Boolean.FALSE;
  private String key;
  private String pin;
  private String regex;

  public DataSet() {
  }

  @Override
  public String toString() {
    return "DataSet{" +
        "hasRegex=" + hasRegex +
        ", key='" + key + '\'' +
        ", pin='" + pin + '\'' +
        ", regex='" + regex + '\'' +
        '}';
  }

  public Boolean getHasRegex() {
    return hasRegex;
  }

  public void setHasRegex(Boolean hasRegex) {
    this.hasRegex = hasRegex;
  }

  public String getKey() {
    return key;
  }

  public void setKey(String key) {
    this.key = key;
  }

  public String getPin() {
    return pin;
  }

  public void setPin(String key) {
    if (key != null) {
      this.pin = Integer.toString(new GoogleAuthenticator().getTotpPassword(key));
    }
  }

  public String getRegex() {
    return regex;
  }

  public void setRegex(String regex) {
    this.regex = regex;
  }
}
