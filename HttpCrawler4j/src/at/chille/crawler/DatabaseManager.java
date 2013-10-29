package at.chille.crawler;

import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.inject.Inject;
import javax.inject.Named;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.crawler.database.model.CrawlingSession;
import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.repository.CertificateRepository;
import at.chille.crawler.database.repository.CrawlingSessionRepository;
import at.chille.crawler.database.repository.HeaderRepository;
import at.chille.crawler.database.repository.HostInfoRepository;
import at.chille.crawler.database.repository.PageInfoRepository;
import edu.uci.ics.crawler4j.url.WebURL;

@Component
public class DatabaseManager
{
  private static ClassPathXmlApplicationContext context = null;
  private static DatabaseManager                _instance;

  protected CrawlingSession                     currentCrawlingSession;

  public static DatabaseManager getInstance()
  {
    if (_instance == null)
    {
      _instance = DatabaseManager.getContext().getBean(
          DatabaseManager.class);
    }
    return _instance;
  }

  /**
   * This method is deprecated because it is too slow for huge datasets. (5000 HostInfo --> 35
   * seconds) Use saveHostInfo(..) instead! Use it only if you generate the session!
   */
  @Deprecated
  public synchronized void saveSession()
  {
    if (currentCrawlingSession == null)
    {
      throw new NullPointerException();
    }
    // "Saves a given entity. Use the returned instance for further
    // operations as the save operation might have changed the entity
    // instance completely."
    currentCrawlingSession = crawlingSessionRepository
        .save(currentCrawlingSession);
  }

  public void tryAddingSomething()
  {
    // not synchronized on purpose: not necessary
    this.setNewCrawlingSession("Dummy Crawling Session - no real content.");
    HostInfo h = new HostInfo();
    h.setHostName("dummy host");
    this.addHostInfo(h);
    this.saveSession();
  }

  public synchronized HostInfo saveHostInfo(HostInfo hi)
  {
    // Reminder: Double store, because by saving the object changes.
    // if it is not restored, it is saved again, and all certificates
    // occur twice in the database everytime the hostInfo is saved.
    currentCrawlingSession.addHostInfo(hi);
    hi = hostInfoRepository.save(hi);
    currentCrawlingSession.addHostInfo(hi);
    return hi;
  }

  public synchronized void setNewCrawlingSession(String description)
  {
    currentCrawlingSession = new CrawlingSession();
    currentCrawlingSession.setDescription(description);
    currentCrawlingSession.setTimeStarted(new Date().getTime());
    // crawlingSessionRepository.save(currentCrawlingSession);
  }

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

  public CrawlingSession getCurrentCrawlingSession()
  {
    // not synchronized on purpose: not necessary
    return this.currentCrawlingSession;
  }

  public HashMap<String, Lock> lockedHosts = new HashMap<String, Lock>();

  public Lock getHostLock(String hostName)
  {
    if (!lockedHosts.containsKey(hostName))
      lockedHosts.put(hostName, new ReentrantLock());
    return lockedHosts.get(hostName);
  }

  public at.chille.crawler.database.model.HostInfo getHostInfo(String hostName)
  {
    // not synchronized on purpose: not necessary
    HostInfo toReturn = currentCrawlingSession.getHosts().get(hostName);
    return toReturn;
  }

  public static String getFullDomain(WebURL webUrl)
  {
    String fullDomain;
    if (webUrl.getSubDomain().length() > 0)
      fullDomain = webUrl.getSubDomain().toLowerCase() + "."
          + webUrl.getDomain().toLowerCase();
    else
      fullDomain = webUrl.getDomain().toLowerCase();
    return fullDomain;
  }

  public synchronized void addHostInfo(
      at.chille.crawler.database.model.HostInfo hostInfo)
  {
    currentCrawlingSession.addHostInfo(hostInfo);
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
  HostInfoRepository        hostInfoRepository;
  @Autowired
  CertificateRepository     certificateRepository;
  @Autowired
  PageInfoRepository        pageInfoRepository;
  @Autowired
  CrawlingSessionRepository crawlingSessionRepository;
  @Autowired
  HeaderRepository          headerRepository;

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
  }

}
