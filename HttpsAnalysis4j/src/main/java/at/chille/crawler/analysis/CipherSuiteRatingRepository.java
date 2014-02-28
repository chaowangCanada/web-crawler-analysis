package at.chille.crawler.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import at.chille.crawler.database.model.sslchecker.CipherSuite;
import javassist.NotFoundException;

public class CipherSuiteRatingRepository {

  private static final CipherSuiteRatingRepository _instance = new CipherSuiteRatingRepository();
  private static Map<String, SslRating> handshakeRatings;
  private static Map<String, SslRating> cipherRatings;
  private static Map<String, SslRating> hashRatings;
  private static Map<String, SslRating> bitsOfBulkCipherRatings;
  private static Map<String, SslRating> tlsVersionRatings;
  private static SslRating previous;
  
  private CipherSuiteRatingRepository() {
    handshakeRatings        = new HashMap<String, SslRating>();
    cipherRatings           = new HashMap<String, SslRating>();
    hashRatings             = new HashMap<String, SslRating>();
    bitsOfBulkCipherRatings = new HashMap<String, SslRating>();
    tlsVersionRatings       = new HashMap<String, SslRating>();
  }
  
  public static CipherSuiteRatingRepository getInstance() {
    return _instance;
  }
  
  public synchronized void addHandshakeRating(String name, SslRating rating) { 
    if (!handshakeRatings.containsKey(name))
      handshakeRatings.put(name, rating);
    else if (handshakeRatings.get(name).getValue() != rating.getValue()) {
      previous = handshakeRatings.put(name, rating);
      System.out.println("Overwritten Handshake-Rating " + name + ": " 
          + previous.getValue() + "  with new Rating: " + rating.getValue());
    }
  }

  public synchronized void addCipherRating(String name, SslRating rating) {
    if (!cipherRatings.containsKey(name))
      cipherRatings.put(name, rating);
    else if (cipherRatings.get(name).getValue() != rating.getValue()) {
      previous = cipherRatings.put(name, rating);
      System.out.println("Overwritten Cipher-Rating " + name + ": " 
          + previous.getValue() + "  with new Rating: " + rating.getValue());
    }
  }

  public synchronized void addHashRating(String name, SslRating rating) {
    if (!hashRatings.containsKey(name))
      hashRatings.put(name, rating);
    else if (hashRatings.get(name).getValue() != rating.getValue()) {
      previous = hashRatings.put(name, rating);
      System.out.println("Overwritten Hash-Rating " + name + ": " 
          + previous.getValue() + "  with new Rating: " + rating.getValue());
    }
  }
  
  public synchronized void addBitsOfBulkCipherRating(String name, SslRating rating) {
    if (!bitsOfBulkCipherRatings.containsKey(name))
      bitsOfBulkCipherRatings.put(name, rating);
    else if (bitsOfBulkCipherRatings.get(name).getValue() != rating.getValue()) {
      previous = bitsOfBulkCipherRatings.put(name, rating);
      System.out.println("Overwritten Bits-of-BulkCipher-Rating " + name + ": " 
          + previous.getValue() + "  with new Rating: " + rating.getValue());
    }
  }
  
  public synchronized void addTlsVersionRating(String name, SslRating rating) {
    if (!tlsVersionRatings.containsKey(name))
      tlsVersionRatings.put(name, rating);
    else if (tlsVersionRatings.get(name).getValue() != rating.getValue()) {
      previous = tlsVersionRatings.put(name, rating);
      System.out.println("Overwritten Tls-Version-Rating " + name + ": " 
          + previous.getValue() + "  with new Rating: " + rating.getValue());
    }
  }

  public synchronized SslRating getCipherRating(CipherSuite cs) 
      throws NotFoundException, NullPointerException {
    
    if (cs == null)
      throw new NullPointerException("The passed CipherSuite in CipherSuiteRatingRepository.getCipherRating is null!");
    
    String csString = cs.getCipherSuite();
    
    // generate sub strings
    List<String> subStrings  = new ArrayList<String>();
    
    while (csString != null) {
      int minus = csString.indexOf("-");
      
      if (minus == -1)
      {
        subStrings.add(csString);
        csString = null;
      }
      else
      {
        subStrings.add(csString.substring(0, minus));
        csString = csString.substring(minus+1, csString.length());
      }
    }
    
    // get the rating for the handshake, bulk cipher and hash method of the CipherSuite
    SslRating handshake = parseSubStrings(handshakeRatings, subStrings);
    SslRating cipher    = parseSubStrings(cipherRatings, subStrings);
    SslRating hash      = parseSubStrings(hashRatings, subStrings);

    if (!subStrings.isEmpty())
      throw new NotFoundException("The following CipherSuite could not be parsed: " + 
                  cs.getCipherSuite() + "! Please update the corresponding xml-file.");
    
    // NULL has to be defined for the different ratings in the xml-file
    if (handshake == null)
      handshake = handshakeRatings.get("NULL");
    if (cipher == null)
      cipher = cipherRatings.get("NULL");
    if (hash == null)
      hash = hashRatings.get("NULL");
    
    // NULL must be present for all types in the xml-file
    if (handshake == null || cipher == null || hash == null)
      throw new NotFoundException("\"NULL\" could not be found for the rating of the "
          + "handshake, bulk cipher or hash method in the xml-file! "
          + "Please update the corresponding xml-file.");
    
    // get the rating for the tls version and for the amount of bits used for the encryption of bulk ciphers
    SslRating tlsVersion = tlsVersionRatings.get(cs.getTlsVersion());
    SslRating bitsOfBulkCipher = bitsOfBulkCipherRatings.get(Integer.toString(cs.getBits()));
    
    if (tlsVersion == null)
      throw new NotFoundException("The following tls version could not be parsed: " + 
                                  cs.getTlsVersion() + "! Please update the corresponding xml-file.");
    else if (bitsOfBulkCipher == null)
      throw new NotFoundException("The following amount of bits for the bulk cipher could not be parsed: " +
                                  cs.getBits() + "! Please update the corresponding xml-file.");
    
    // finally calculate the rating for the whole CipherSuite
    double finalValue = handshake.getValue() + (cipher.getValue()+bitsOfBulkCipher.getValue())*0.7 + 
                        hash.getValue()*0.3 + tlsVersion.getValue();
    String description = handshake.getDescription() + "." + cipher.getDescription() + "." + 
                         hash.getDescription() + "." + bitsOfBulkCipher.getDescription() + "." + 
                         tlsVersion.getDescription();
    
    return new SslRating(finalValue, cs, description);
  }
  
  private SslRating parseSubStrings(Map<String, SslRating> mapToCheck, List<String> subStrings)
  {
    int position           = -1;
    SslRating tmpRating    = null;
    SslRating returnRating = null;
    String tmpCheck        = subStrings.get(0);
    
    for (int i = 0; i < subStrings.size(); i++)
    {
      if (i > 0)
        tmpCheck = tmpCheck + "-" + subStrings.get(i);
      
      tmpRating = mapToCheck.get(tmpCheck);
      if (tmpRating != null)
      {
        position = i;
        returnRating = tmpRating;
      }
    }
    
    if (position != -1)
      for (int i = 0; i <= position; i++)
        subStrings.remove(0);
    
    return returnRating;
  }

}
