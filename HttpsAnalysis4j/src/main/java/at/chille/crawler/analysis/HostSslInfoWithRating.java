package at.chille.crawler.analysis;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.HashSet;
import java.util.Set;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * extends the class HostSslInfo by security rating attributes
 * 
 * @author kwk
 * 
 */
public class HostSslInfoWithRating extends HostSslInfo {
	
    private Set<SslRating> securityRatingsAccepted;
    private Set<SslRating> securityRatingsPreferred;
    private double overallRating;
    
    public HostSslInfoWithRating()
    {
      super();
      this.securityRatingsAccepted  = new HashSet<SslRating>();
      this.securityRatingsPreferred = new HashSet<SslRating>();
    }

    public Set<SslRating> getSecurityRatingsAccepted() {
      return securityRatingsAccepted;
    }

    public void setSecurityRatingsAccepted(Set<SslRating> securityRatingsAccepted) {
      this.securityRatingsAccepted = securityRatingsAccepted;
    }
    
    public void addSslRatingToSecurityRatingsAccepted(SslRating sslRating) {
      this.securityRatingsAccepted.add(sslRating);
    }

    public Set<SslRating> getSecurityRatingsPreferred() {
      return securityRatingsPreferred;
    }

    public void setSecurityRatingsPreferred(Set<SslRating> securityRatingsPreferred) {
      this.securityRatingsPreferred = securityRatingsPreferred;
    }
    
    public void addSslRatingToSecurityRatingsPreferred(SslRating sslRating) {
      this.securityRatingsPreferred.add(sslRating);
    }

    public double getOverallRating() {
      return overallRating;
    }

    public void calculateOverallRating() {
      double sumOfRatingsAccepted  = 0;
      double sumOfRatingsPreferred = 0;
      
      for (SslRating r : securityRatingsAccepted) 
        sumOfRatingsAccepted += r.getValue();
      for (SslRating r : securityRatingsPreferred) 
        sumOfRatingsPreferred += r.getValue();
      
      sumOfRatingsAccepted  /= securityRatingsAccepted.size();
      sumOfRatingsPreferred /= securityRatingsPreferred.size();
      
      double oRNotRounded = sumOfRatingsAccepted*0.25 + sumOfRatingsPreferred*0.75;
      
      if (!Double.isNaN(oRNotRounded))
        this.overallRating = new BigDecimal(oRNotRounded).setScale(2, RoundingMode.HALF_UP).doubleValue();
      else {
        System.out.println("WARNING: List of accepted and/or preferred Cipher-Suites is empty for host " 
                            + this.getHostSslName() + "!");
        this.overallRating = oRNotRounded;
      }
    }
}
