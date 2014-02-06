package at.chille.crawler.analysis;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * extends the class HostSslInfo by a securityRating-attribute
 * 
 * @author acn
 * 
 */
public class HostSslInfoWithRating extends HostSslInfo {
	
    private long securityRating;
    
    public HostSslInfoWithRating()
    {
      super();
      setSecurityRating(0L);
    }

    public long getSecurityRating() {
      return securityRating;
    }

    public void setSecurityRating(long securityRating) {
      this.securityRating = securityRating;
    }
}
