package at.chille.crawler.sslchecker;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.tika.metadata.Metadata;

import edu.uci.ics.crawler4j.url.WebURL;
import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * @author chille
 * 
 */
public class HttpsChecker implements Runnable
{
  protected HashSet<String>     WHITELIST              = new HashSet<String>();

  protected long                niceWaitTime           = 500;

  // lower priorities will be fetched earlier!
  protected byte                PRIORITY_WHITELIST     = 10;
  protected byte                PRIORITY_INSPECT_HTTP  = 5;
  protected byte                PRIORITY_INSPECT_HTTPS = 5;

  public HttpsChecker()
  {
    for (String whitelist : StringFileReader.readLines("url-whitelist.txt"))
    {
      // System.out.println("URL: Whiteliste: "+whitelist);
      WHITELIST.add(whitelist.toLowerCase());
    }
  }

  public boolean visit(HostInfo hostInfo)
  {
	  System.out.println("SSL-checking host " + hostInfo.getHostName());
	  return false;
  }
  
  /**
   * Decides if the given HostInfo should be visited for SSL-checking. 
   * Returns true if the host was not visited yet.
   * 
   * @param 
   * @return true if the URL should be visited
   */
  public boolean shouldVisitForInspection(HostInfo hostInfo)
  {
//	  DatabaseManager.getInstance().getHostSSLInfoRepository().
//    String fullDomain = DatabaseManager.getFullDomain(webUrl);
//    String href = webUrl.getURL().toLowerCase();
//
//    if (webUrl.getDomain().endsWith("at"))
//    {
//
//      DatabaseManager.getInstance().getHostLock(fullDomain).lock();
//      HostInfo hostInfo = DatabaseManager.getInstance().getHostInfo(fullDomain);
//      if (hostInfo == null)
//      {
//        hostInfo = new HostInfo();
//        hostInfo.setHostName(fullDomain);
//        hostInfo.getTodoUrls().add(href);
//        DatabaseManager.getInstance().addHostInfo(hostInfo);
//        DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
//        return true;
//      }
//
//      if (hostInfo.getTodoUrls().contains(href))
//      {
//        DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
//        return false;
//      }
//      
//      DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
//    }
    return false;
  }

  /**
   * Returns the time to wait before fetching the given URL. Must Return zero if we don't have to
   * Sleep.
   * 
   * @param url
   * @return
   */
//  public long getNiceWaitTime(WebURL url)
//  {
//    String fullDomain = DatabaseManager.getFullDomain(url);
//    HostInfo host = DatabaseManager.getInstance().getHostInfo(fullDomain);
//
//    DatabaseManager.getInstance().getHostLock(fullDomain).lock();
//    if (host == null)
//    {
//      host = new HostInfo();
//      host.setHostName(DatabaseManager.getFullDomain(url));
//      host.setLastVisited(new Date().getTime());
//      DatabaseManager.getInstance().addHostInfo(host);
//      host = DatabaseManager.getInstance().saveHostInfo(host);
//      DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
//      return 0;
//    }
//
//    long now = new Date().getTime();
//    long timeToWait = host.getLastVisited() + niceWaitTime - now;
//    if (timeToWait <= 0)
//    {
//      host.setLastVisited(now);
//      // here it is not important to store to the database.
//      //DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
//      return 0;
//    }
//    else
//    {
//      // System.err.println("Waiting: " + host.getHostName() + ": "
//      // + timeToWait);
//    }
//    // System.err.println("Check Nice: " + host.getHostName() +
//    // ": now: "
//    // + now + " this: " + thisVisit + " wait: " + timeToWait);
//    //DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
//    return timeToWait;
//  }

  @Override
  public void run()
  {
    while (true)
    {
      int maxFetch = 20;

      // maxFetch = (int) (2 * frontier.getQueueLength() /
      // HttpAnalysisCrawlController.threads);
      // if (maxFetch > 20) {
      // maxFetch = 20;
      // }
      // if (maxFetch < 1) {
      // maxFetch = 1;
      // }
      List<WebURL> assignedURLs = new ArrayList<WebURL>(maxFetch);
      return;
    }
  }
}
