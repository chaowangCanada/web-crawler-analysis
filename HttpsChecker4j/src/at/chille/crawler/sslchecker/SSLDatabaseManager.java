package at.chille.crawler.sslchecker;

import java.util.Map;
import javax.inject.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.crawler.database.model.*;
import at.chille.crawler.database.model.sslchecker.*;
import at.chille.crawler.database.repository.*;
import at.chille.crawler.database.repository.sslchecker.*;

/**
 * Database Manager for HttpsChecker4j
 * 
 * @author chille
 * 
 */
@Component
public class SSLDatabaseManager
{
  private static ClassPathXmlApplicationContext context = null;
  private static SSLDatabaseManager                _instance;

  protected CrawlingSession		 	  currentCrawlingSession;
  
  public static SSLDatabaseManager getInstance()
  {
    if (_instance == null)
    {
      _instance = SSLDatabaseManager.getContext().getBean(
          SSLDatabaseManager.class);
    }
    return _instance;
  }
  
//  @Deprecated
//  public synchronized void saveSession()
//  {
//    if (currentCrawlingSession == null)
//    {
//      throw new NullPointerException();
//    }
//    // "Saves a given entity. Use the returned instance for further
//    // operations as the save operation might have changed the entity
//    // instance completely."
//    currentCrawlingSession = crawlingSessionRepository
//        .save(currentCrawlingSession);
//  }
  
//  public synchronized HostSslInfo saveHostInfo(HostSslInfo hi)
//  {
//    // Reminder: Double store, because by saving the object changes.
//    // if it is not restored, it is saved again, and all certificates
//    // occur twice in the database every time the hostInfo is saved.
//	currentSslSession.addHostSslInfo(hi);
//    hi = hostSslInfoRepository.save(hi);
//    currentSslSession.addHostSslInfo(hi);
//    return hi;
//  }

//  public synchronized void setNewSslSession(String description)
//  {
//	  currentSslSession = new SslSession();
//	  currentSslSession.setDescription(description);
//	  currentSslSession.setTimeStarted(new Date().getTime());
//      //currentSslSession.save(currentSslSession);
//  }

//  public void loadLastSslSession()
//  {
//    long timeStartedMax = 0;
//    for (SslSession cs : sslSessionRepository.findAll())
//    {
//      if (cs.getTimeStarted().longValue() > timeStartedMax)
//      {
//        timeStartedMax = cs.getTimeStarted().longValue();
//        this.currentSslSession = cs;
//      }
//    }
//  }
  
  public void loadLastCrawlingSession()
  {
    long timeStartedMax = 0;
    for (CrawlingSession cs : crawlingSessionRepository.findAll())
    {
      if (cs.getTimeStarted().longValue() > timeStartedMax)
      {
        timeStartedMax = cs.getTimeStarted().longValue();
        this.currentCrawlingSession = cs;
      }
    }
  }
  
  public synchronized CipherSuite saveCipherSuite(CipherSuite cs)
  {
	  try{
		  return cipherSuiteRepository.save(cs);
	  } catch(Exception e)
	  {
		  e.printStackTrace();
	  }
	  return null;
  }

  public Map<String, HostInfo> getAllHosts()
  {
	  return currentCrawlingSession.getHosts();
  }
  
  protected static synchronized ApplicationContext getContext()
  {
    if (context == null)
    {
      context = new ClassPathXmlApplicationContext();
      String[] locations =
      { "classpath*:resthubContext.xml",
          "classpath*:application-context-democlient.xml",
    		  };
      context.getEnvironment().setActiveProfiles("resthub-jpa");
      context.setConfigLocations(locations);

      context.refresh();
    }

    return context;
  }

  
//  @Autowired
//  HostInfoRepository        hostInfoRepository;
//  @Autowired
//  CertificateRepository     certificateRepository;
//  @Autowired
//  PageInfoRepository        pageInfoRepository;
  @Autowired
  private CrawlingSessionRepository crawlingSessionRepository;
//  @Autowired
//  HeaderRepository          headerRepository;

//  @Inject
//  @Named("hostInfoRepository")
//  public void setHostInfoRepository(HostInfoRepository t)
//  {
//    this.hostInfoRepository = t;
//  }

//  @Inject
//  @Named("certificateRepository")
//  public void setCertificateRepository(CertificateRepository t)
//  {
//    this.certificateRepository = t;
//  }

//  @Inject
//  @Named("pageInfoRepository")
//  public void setPageInfoRepository(PageInfoRepository t)
//  {
//    this.pageInfoRepository = t;
//  }

  @Inject
  @Named("crawlingSessionRepository")
  public void setCrawlingSessionRepository(CrawlingSessionRepository t)
  {
    this.crawlingSessionRepository = t;
  }
  
  @Autowired
  private HostSslInfoRepository        hostSslInfoRepository;
  @Autowired
  private CipherSuiteRepository		   cipherSuiteRepository;
//  @Autowired
//  SslSessionRepository         sslSessionRepository;
//
  public HostSslInfoRepository getHostSSLInfoRepository()
  {
    return hostSslInfoRepository;
  }
  
  public CipherSuiteRepository getCipherSuiteRepository()
  {
    return cipherSuiteRepository;
  }

//  public SslSessionRepository getSslSessionRepository()
//  {
//    return sslSessionRepository;
//  }


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
  
//  @Autowired
//  HeaderRepository         headerRepository;
  
//  @Inject
//  @Named("headerRepository")
//  public void setHeaderRepository(HeaderRepository t)
//  {
//    this.headerRepository = t;
//  }
  
//  @Inject
//  @Named("sslSessionRepository")
//  public void setSslSessionRepository(SslSessionRepository t)
//  {
//    this.sslSessionRepository = t;
//  }
}
