package at.chille.crawler.analysis;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * extends the class HostSslInfo by security rating attributes
 * 
 * @author kwk
 * 
 */
public class HostSslInfoWithRating extends HostSslInfo {
	
    private List<SslRating> securityRatingsAccepted;
    private List<SslRating> securityRatingsPreferred;
    private double overallRating;
    
    public HostSslInfoWithRating() {
      super();
      this.securityRatingsAccepted  = new ArrayList<SslRating>();
      this.securityRatingsPreferred = new ArrayList<SslRating>();
    }
    
    public HostSslInfoWithRating(HostSslInfo hsi) {
      this();
      this.addAccepted(hsi.getAccepted());
      this.addFailed(hsi.getFailed());
      this.addPreferred(hsi.getPreferred());
      this.addRejected(hsi.getRejected());
      this.setHostSslName(hsi.getHostSslName());
      this.setTimestamp(hsi.getTimestamp());
    }

    public List<SslRating> getSecurityRatingsAccepted() {
      return securityRatingsAccepted;
    }

    public void setSecurityRatingsAccepted(List<SslRating> securityRatingsAccepted) {
      this.securityRatingsAccepted = securityRatingsAccepted;
    }
    
    public void addSslRatingToSecurityRatingsAccepted(SslRating sslRating) {
      this.securityRatingsAccepted.add(sslRating);
    }

    public List<SslRating> getSecurityRatingsPreferred() {
      return securityRatingsPreferred;
    }

    public void setSecurityRatingsPreferred(List<SslRating> securityRatingsPreferred) {
      this.securityRatingsPreferred = securityRatingsPreferred;
    }
    
    public void addSslRatingToSecurityRatingsPreferred(SslRating sslRating) {
      this.securityRatingsPreferred.add(sslRating);
    }

    public double getOverallRating() {
      return overallRating;
    }

    public void calculateOverallRating(Set<String> acceptedEmpty, Set<String> preferredEmpty) {
      double sumOfRatingsAccepted  = 0;
      double sumOfRatingsPreferred = 0;
      
      for (SslRating r : securityRatingsAccepted) 
        sumOfRatingsAccepted += r.getValue();
      for (SslRating r : securityRatingsPreferred) 
        sumOfRatingsPreferred += r.getValue();
      
      sumOfRatingsAccepted  /= securityRatingsAccepted.size();
      sumOfRatingsPreferred /= securityRatingsPreferred.size();
      
      if (Double.isNaN(sumOfRatingsAccepted))
        acceptedEmpty.add(this.getHostSslName());
      
      if (Double.isNaN(sumOfRatingsPreferred))
        preferredEmpty.add(this.getHostSslName());
      
      double oRNotRounded = sumOfRatingsAccepted*0.25 + sumOfRatingsPreferred*0.75;
      
      if (!Double.isNaN(oRNotRounded)) {
        this.overallRating = new BigDecimal(oRNotRounded).setScale(2, RoundingMode.HALF_UP).doubleValue();
      }
      else {
        this.overallRating = oRNotRounded;
      }
    }
    
    public void sortSecurityRatingsSets() {
      Collections.sort(this.securityRatingsPreferred, new ComparatorSslRating());
      Collections.sort(this.securityRatingsAccepted, new ComparatorSslRating());
    }
}
