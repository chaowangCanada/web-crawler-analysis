package at.chille.crawler.analysis;

import javax.inject.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.crawler.database.repository.*;

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
  HostInfoRepository        hostInfoRepository;
  @Autowired
  CertificateRepository     certificateRepository;
  @Autowired
  PageInfoRepository        pageInfoRepository;
  @Autowired
  CrawlingSessionRepository crawlingSessionRepository;
  @Autowired
  HeaderRepository          headerRepository;

  public HostInfoRepository getHostInfoRepository()
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
  }
}
