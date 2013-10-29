package at.chille.crawler.analysis;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import at.chille.crawler.database.model.HostInfo;

public class AnalysisCertIssuers extends Analysis
{

  public AnalysisCertIssuers()
  {
    super();
  }

  public AnalysisCertIssuers(boolean showDetails)
  {
    super(showDetails);
  }

  public AnalysisCertIssuers(long useCrawlingSessionID, boolean showDetails)
  {
    super(useCrawlingSessionID, showDetails);
  }

  @Override
  public void init()
  {
    this.name = "CertIssuers";
    this.description = "Which Root Certificates are used?";
  }

  protected Map<Principal, List<HostInfo>> issuers = new HashMap<Principal, List<HostInfo>>();

  @Override
  public int analyze()
  {
    // CrawlingSession cs = this.selectCrawlingSession();
    Collection<HostInfo> hostInfos = this.getHostsToAnalyze();

    issuers.clear();
    // out.println(cs.getTimeStarted() + " - " + cs.getDescription());
    for (HostInfo hi : hostInfos)
    {
      List<X509Certificate> certs = CertificateSorter
          .sortCertificates(CertificateSorter.parseCertificates(hi.getCert()));

      if (certs.size() > 0)
      {
        X509Certificate root = certs.get(certs.size() - 1);
        Principal issuer = root.getIssuerDN();
        if (!issuers.containsKey(issuer))
        {
          issuers.put(issuer, new ArrayList<HostInfo>());
        }
        issuers.get(issuer).add(hi);
      }
    }
    for (Map.Entry<Principal, List<HostInfo>> issuer : issuers.entrySet())
    {
      out.println(issuer.getKey() + " (" + issuer.getValue().size() + ")");
      if (this.showDetails)
      {
        for (HostInfo hi : issuer.getValue())
        {
          out.println("  " + hi.getHostName() + " -> " + hi.getSslProtocol() + ", "
              + hi.getCipherSuite());
        }
      }
    }
    return 0;

  }

}
