package at.chille.crawler.analysis;

import java.util.HashMap;
import java.util.Map;

import javax.inject.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.database.repository.sslchecker.CipherSuiteRepository;
import at.chille.crawler.database.repository.sslchecker.HostSslInfoRepository;

/**
 * Database Manager for Analysis
 * 
 * @author chille
 * 
 */
@Component
public class DatabaseManager
{
  private static ClassPathXmlApplicationContext context = null;
  private static DatabaseManager                _instance;
  private Map<String, HostSslInfo> lastRecentHostSslInfos;

  public static DatabaseManager getInstance()
  {
    if (_instance == null)
    {
      _instance = DatabaseManager.getContext().getBean(
          DatabaseManager.class);
    }
    return _instance;
  }

  protected static synchronized ApplicationContext getContext()
  {
    if (context == null)
    {
      context = new ClassPathXmlApplicationContext();
      String[] locations =
      { "classpath*:resthubContext.xml",
          "classpath*:application-context-democlient.xml" };
      context.getEnvironment().setActiveProfiles("resthub-jpa");
      context.setConfigLocations(locations);

      context.refresh();
    }

    return context;
  }
  
  @Autowired
  private HostSslInfoRepository        hostSslInfoRepository;
  @Autowired
  private CipherSuiteRepository		   cipherSuiteRepository;
  
  public HostSslInfoRepository getHostSSLInfoRepository()
  {
    return hostSslInfoRepository;
  }
  
  public CipherSuiteRepository getCipherSuiteRepository()
  {
    return cipherSuiteRepository;
  }
  
  @Inject
  @Named("hostSslInfoRepository")
  public void setHostSslInfoRepository(HostSslInfoRepository t)
  {
    this.hostSslInfoRepository = t;
  }

  @Inject
  @Named("cipherSuiteRepository")
  public void setCipherSuiteRepository(CipherSuiteRepository t)
  {
    this.cipherSuiteRepository = t;
  }

  /**
   * Load the last scanned SSL-hosts from the db. This is used to
   * speedup further calls to getMostRecentHostSslInfo. 
   */
  public synchronized void loadLastRecentHostSslInfos()
  {
    lastRecentHostSslInfos = new HashMap<String, HostSslInfo>();
    Iterable<HostSslInfo> hosts = hostSslInfoRepository.findAll();
    for (HostSslInfo h : hosts) {
      HostSslInfo lastInfo = lastRecentHostSslInfos.get(h.getHostSslName());
      if(lastInfo == null) {
        lastRecentHostSslInfos.put(h.getHostSslName(), h);
      } else {
        Long lastTimestamp = lastInfo.getTimestamp() == null ? 
            0L : lastInfo.getTimestamp();
        Long currentTimestamp = h.getTimestamp() == null ? 
            0L : h.getTimestamp();
        
        if (currentTimestamp > lastTimestamp) {
          //found a newer HostSslInfo
          lastRecentHostSslInfos.put(h.getHostSslName(), h);
        }
      }
    }
  }
  
  /**
   * Return the most recent HostSslInfo object from previous scans.
   * loadLastHostSslInfos must be called once before.
   * @param host to search for
   * @return the most recent HostSslInfo object or null
   */
  public synchronized HostSslInfo getMostRecentHostSslInfo(String host) {
    return lastRecentHostSslInfos.get(host);
  }
  
  public synchronized Map<String, HostSslInfo> getLastHostSslInfos() {
    return lastRecentHostSslInfos;
  }
  
  /*@Autowired
  HostInfoRepository        hostInfoRepository;
  @Autowired
  CertificateRepository     certificateRepository;
  @Autowired
  PageInfoRepository        pageInfoRepository;
  @Autowired
  CrawlingSessionRepository crawlingSessionRepository;
  @Autowired
  HeaderRepository          headerRepository;*/

  /*public HostInfoRepository getHostInfoRepository()
  {
    return hostInfoRepository;
  }

  public CertificateRepository getCertificateRepository()
  {
    return certificateRepository;
  }

  public PageInfoRepository getPageInfoRepository()
  {
    return pageInfoRepository;
  }

  public CrawlingSessionRepository getCrawlingSessionRepository()
  {
    return crawlingSessionRepository;
  }

  public HeaderRepository getHeaderRepository()
  {
    return headerRepository;
  }

  @Inject
  @Named("hostInfoRepository")
  public void setHostInfoRepository(HostInfoRepository t)
  {
    this.hostInfoRepository = t;
  }

  @Inject
  @Named("certificateRepository")
  public void setCertificateRepository(CertificateRepository t)
  {
    this.certificateRepository = t;
  }

  @Inject
  @Named("pageInfoRepository")
  public void setPageInfoRepository(PageInfoRepository t)
  {
    this.pageInfoRepository = t;
  }

  @Inject
  @Named("crawlingSessionRepository")
  public void setCrawlingSessionRepository(CrawlingSessionRepository t)
  {
    this.crawlingSessionRepository = t;
  }

  @Inject
  @Named("headerRepository")
  public void setHeaderRepository(HeaderRepository t)
  {
    this.headerRepository = t;
  }*/
}
