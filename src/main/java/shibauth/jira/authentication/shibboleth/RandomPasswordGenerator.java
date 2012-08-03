package shibauth.jira.authentication.shibboleth;

import java.security.SecureRandom;
import java.math.BigInteger;

public final class RandomPasswordGenerator
{
  private SecureRandom random = new SecureRandom();

  public String generatePassword() {
    return new BigInteger(130, random).toString(32);
  }

  public static String getPassword() {
    RandomPasswordGenerator x = new RandomPasswordGenerator();
    return(x.generatePassword());
  }

  public static void main(String[] args) {
    System.out.println(RandomPasswordGenerator.getPassword());
  }

}
