package at.chille.crawler.analysis;

import java.util.HashSet;
import java.util.Set;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * extends the class HostSslInfo by security rating attributes
 * 
 * @author acn
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
      
      this.overallRating = sumOfRatingsAccepted*0.25 + sumOfRatingsPreferred; 
    }
}
