package at.chille.sslchecker;

import javax.inject.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.sslchecker.database.repository.*;

/**
 * Database Manager for HttpsChecker4j
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
  HostSSLInfoRepository        hostSSLInfoRepository;
  @Autowired
  SSLSessionRepository         sslSessionRepository;

  public HostSSLInfoRepository getHostSSLInfoRepository()
  {
    return hostSSLInfoRepository;
  }

  public SSLSessionRepository getSSLSessionRepository()
  {
    return sslSessionRepository;
  }


  @Inject
  @Named("hostSSLInfoRepository")
  public void setHostSSLInfoRepository(HostSSLInfoRepository t)
  {
    this.hostSSLInfoRepository = t;
  }

  @Inject
  @Named("sslSessionRepository")
  public void setSSLSessionRepository(SSLSessionRepository t)
  {
    this.sslSessionRepository = t;
  }
}
