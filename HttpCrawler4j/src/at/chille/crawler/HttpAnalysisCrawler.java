package at.chille.crawler;

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

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.PageInfo;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.crawler.WebCrawler;
import edu.uci.ics.crawler4j.fetcher.CustomFetchStatus;
import edu.uci.ics.crawler4j.fetcher.PageFetchResult;
import edu.uci.ics.crawler4j.parser.HtmlParseData;
import edu.uci.ics.crawler4j.parser.ParseData;
import edu.uci.ics.crawler4j.url.WebURL;

/**
 * @author chille
 * 
 */
public class HttpAnalysisCrawler extends WebCrawler
{
  private final static Pattern  FILTERS                = Pattern
                                                           .compile(".*(\\.(css|js|bmp|gif|ico|jpe?g"
                                                               + "|png|tiff?|mid|mp2|mp3|mp4"
                                                               + "|wav|avi|mov|mpeg|ram|m4v|pdf"
                                                               + "|rm|smil|wmv|swf|wma|zip|rar|gz))$");

  protected HashSet<String>     WHITELIST              = new HashSet<String>();
  protected int                 inspectionLimitPerHost = 1;

  protected long                niceWaitTime           = 500;

  // lower priorities will be fetched earlier!
  protected byte                PRIORITY_WHITELIST     = 10;
  protected byte                PRIORITY_INSPECT_HTTP  = 5;
  protected byte                PRIORITY_INSPECT_HTTPS = 5;

  protected HashSet<String>     interestingHeaders     = new HashSet<String>();
  protected HashSet<String>     blacklistHeaders       = new HashSet<String>();
  protected Map<String, String> detectHTML             = new HashMap<String, String>();

  public HttpAnalysisCrawler()
  {

    for (String whitelist : StringFileReader.readLines("url-whitelist.txt"))
    {
      // System.out.println("URL: Whiteliste: "+whitelist);
      WHITELIST.add(whitelist.toLowerCase());
    }

    for (String blacklist : StringFileReader
        .readLines("headers-blacklist.txt"))
    {
      // System.out.println("Header: Blacklist: "+blacklist);
      blacklistHeaders.add(blacklist.toLowerCase());
    }

    detectHTML.put("googletagservices.com/tag/js/gpt.js".toLowerCase(),
        "Google Publisher Tag");
    detectHTML.put(
        "google.com/recaptcha/api/js/recaptcha_ajax.js".toLowerCase(),
        "Google Recaptcha");
    detectHTML.put("connect.facebook.net/de_DE/all.js".toLowerCase(),
        "Facebook Likes");
    detectHTML.put("facebook.com/plugins/like.php".toLowerCase(),
        "Facebook Likes");
    detectHTML.put("apis.google.com/js/plusone.js".toLowerCase(),
        "Google Plus");
    detectHTML.put(
        "googlesyndication.com/pagead/show_ads.js".toLowerCase(),
        "Google Syndication");
    detectHTML.put(".google-analytics.com/ga.js".toLowerCase(),
        "Google Analytics");
    detectHTML
        .put("//ajax.googleapis.com".toLowerCase(), "Google Ajax API");

    // not so good:
    detectHTML.put("<script type=\"text/javascript\">".toLowerCase(),
        "JSinHTML");
    detectHTML.put("</style>".toLowerCase(), "CSSinHTML");
  }

  /**
   * Counts the number of URLS in visited, that have the same protocol as the URL in current. Only
   * http:// and https:// are known
   * 
   * @param visited
   *          List of URLs to be counted
   * @param current
   *          Url with a specific protocol.
   * @return
   */
  public int countSimilarURLs(Set<String> visited, String current)
  {
    int count = 0;
    String protocol = null;
    if (current.startsWith("https://"))
      protocol = "https://";
    else if (current.startsWith("http://"))
      protocol = "http://";
    for (String url : visited)
    {
      // does the url has the same protocol?
      if (url.startsWith(protocol))
      {
        // TODO: filter by folders?
        count += 1;
      }
    }
    return count;
  }

  /**
   * Decides if the given WebURL should be visited for Inspection. Returns true if the URL was not
   * visited yet and the number of URLs with the same Hostname and the same Protocol is less than
   * this.inspectionLimitPerHost.
   * 
   * @param webUrl
   * @return true if the URL should be visited
   */
  public boolean shouldVisitForInspection(WebURL webUrl)
  {
    String fullDomain = DatabaseManager.getFullDomain(webUrl);
    String href = webUrl.getURL().toLowerCase();

    if (webUrl.getDomain().endsWith("at"))
    {

      DatabaseManager.getInstance().getHostLock(fullDomain).lock();
      HostInfo hostInfo = DatabaseManager.getInstance().getHostInfo(
          fullDomain);
      if (hostInfo == null)
      {
        hostInfo = new HostInfo();
        hostInfo.setHostName(fullDomain);
        hostInfo.getTodoUrls().add(href);
        DatabaseManager.getInstance().addHostInfo(hostInfo);
        DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
        return true;
      }

      if (hostInfo.getPages().containsKey(href))
      {
        DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
        return false;
      }
      if (hostInfo.getTodoUrls().contains(href))
      {
        DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
        return false;
      }
      int similarURLs = countSimilarURLs(hostInfo.getPages().keySet(),
          href);
      similarURLs += countSimilarURLs(hostInfo.getTodoUrls(), href);
      if (similarURLs < inspectionLimitPerHost)
      {
        hostInfo.getTodoUrls().add(href);
        hostInfo = DatabaseManager.getInstance().saveHostInfo(hostInfo);
        // System.out.println("o "+ webUrl.toString());
        DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
        return true;
      }
      DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
    }
    return false;
  }

  @Override
  public boolean shouldVisit(WebURL url)
  {
    String href = url.getURL().toLowerCase();
    if (FILTERS.matcher(href).matches()) // abort on images, ...
      return false;

    boolean returnvalue = false;
    for (String white : WHITELIST)
    {
      if (href.startsWith(white))
      {
        returnvalue = true;
        url.setPriority(this.PRIORITY_WHITELIST);
      }
    }
    if (returnvalue == false)
    {
      returnvalue = shouldVisitForInspection(url);
    }
    // System.out.println(returnvalue+ " --> "+href);
    return returnvalue;
  }

  /**
   * Returns the time to wait before fetching the given URL. Must Return zero if we don't have to
   * Sleep.
   * 
   * @param url
   * @return
   */
  public long getNiceWaitTime(WebURL url)
  {
    String fullDomain = DatabaseManager.getFullDomain(url);
    HostInfo host = DatabaseManager.getInstance().getHostInfo(fullDomain);

    DatabaseManager.getInstance().getHostLock(fullDomain).lock();
    if (host == null)
    {
      host = new HostInfo();
      host.setHostName(DatabaseManager.getFullDomain(url));
      host.setLastVisited(new Date().getTime());
      DatabaseManager.getInstance().addHostInfo(host);
      host = DatabaseManager.getInstance().saveHostInfo(host);
      DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
      return 0;
    }

    long now = new Date().getTime();
    long timeToWait = host.getLastVisited() + niceWaitTime - now;
    if (timeToWait <= 0)
    {
      host.setLastVisited(now);
      // here it is not important to store to the database.
      DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
      return 0;
    }
    else
    {
      // System.err.println("Waiting: " + host.getHostName() + ": "
      // + timeToWait);
    }
    // System.err.println("Check Nice: " + host.getHostName() +
    // ": now: "
    // + now + " this: " + thisVisit + " wait: " + timeToWait);
    DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
    return timeToWait;
  }

  @Override
  public void run()
  {
    onStart();
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
      isWaitingForNewURLs = true;
      frontier.getNextURLs(maxFetch, assignedURLs);
      isWaitingForNewURLs = false;
      if (assignedURLs.size() == 0)
      {
        if (frontier.isFinished())
        {
          return;
        }
        try
        {
          // wait for new urls (currently no urls available)
          Thread.sleep(3000);
        }
        catch (InterruptedException e)
        {
          e.printStackTrace();
        }
      }
      else
      {

        while (assignedURLs.size() > 0)
        {
          WebURL curURL = assignedURLs.remove(0);
          if (curURL != null)
          {
            long wait = getNiceWaitTime(curURL);
            if (wait > 0)
            {
              try
              {
                if (assignedURLs.size() >= 1 && wait > 200)
                {
                  // try another url before, add to queue..
                  // logger.info(curURL.getDomain()
                  // + "  Wait + Try other: "
                  // + curURL.getDomain()
                  // + " Assigned #"
                  // + assignedURLs.size());
                  Thread.sleep(50);
                  assignedURLs.add(curURL);
                  continue;
                }
                else
                {
                  // Really wait
                  // logger.info("  Really Wait for " + wait
                  // + " ms: " + curURL.getDomain()
                  // + " Assigned #"
                  // + assignedURLs.size());
                  Thread.sleep(wait);
                  continue;
                }
              }
              catch (InterruptedException e)
              {
                e.printStackTrace();
              }
            }
            processPage(curURL);
            frontier.setProcessed(curURL);
          }
          if (myController.isShuttingDown())
          {
            logger.info("Exiting because of controller shutdown.");
            return;
          }
        }

        // for (WebURL curURL : assignedURLs) {
        // if (curURL != null) {
        // long timeToSleep = 0;
        // try {
        // while ((timeToSleep = getNiceWaitTime(curURL)) > 0) {
        // Thread.sleep(timeToSleep);
        // }
        // } catch (Exception ex) {
        // ex.printStackTrace();
        // }
        // processPage(curURL);
        // frontier.setProcessed(curURL);
        // }
        // if (myController.isShuttingDown()) {
        // logger.info("Exiting because of controller shutdown.");
        // return;
        // }
        // }

      }
    }
  }

  @Override
  protected void processPage(WebURL curURL)
  {
    if (curURL == null)
    {
      return;
    }
    logger.info("trying to fetch: " + curURL.getURL().toLowerCase());

    PageFetchResult fetchResult = null;
    try
    {
      fetchResult = pageFetcher.fetchHeader(curURL);
      int statusCode = fetchResult.getStatusCode();
      handlePageStatusCode(curURL, statusCode,
          CustomFetchStatus.getStatusDescription(statusCode));
      if (statusCode != HttpStatus.SC_OK)
      {
        if (statusCode == HttpStatus.SC_MOVED_PERMANENTLY
            || statusCode == HttpStatus.SC_MOVED_TEMPORARILY)
        {
          if (myController.getConfig().isFollowRedirects())
          {
            String movedToUrl = fetchResult.getMovedToUrl();
            if (movedToUrl == null)
            {
              return;
            }
            int newDocId = docIdServer.getDocId(movedToUrl);
            if (newDocId > 0)
            {
              // Redirect page is already seen
              return;
            }

            WebURL webURL = new WebURL();
            webURL.setURL(movedToUrl);
            webURL.setParentDocid(curURL.getParentDocid());
            webURL.setParentUrl(curURL.getParentUrl());
            webURL.setDepth(curURL.getDepth());
            webURL.setDocid(-1);
            webURL.setAnchor(curURL.getAnchor());
            if (movedToUrl.startsWith("https://"))
              webURL.setPriority(this.PRIORITY_INSPECT_HTTPS);
            else
              webURL.setPriority(this.PRIORITY_INSPECT_HTTP);

            if (shouldVisit(webURL)
                && robotstxtServer.allows(webURL))
            {
              webURL.setDocid(docIdServer.getNewDocID(movedToUrl));
              frontier.schedule(webURL);
            }
            logger.info("  Moved: " + webURL.getURL());
            // notify Database of redirect!
            String fullDomain = DatabaseManager
                .getFullDomain(webURL);

            DatabaseManager.getInstance().getHostLock(fullDomain)
                .lock();
            HostInfo hostInfo = DatabaseManager.getInstance()
                .getHostInfo(fullDomain);
            if (hostInfo == null)
            {
              hostInfo = new HostInfo();
              hostInfo.setHostName(fullDomain);
              DatabaseManager.getInstance().addHostInfo(hostInfo);
            }

            PageInfo page = new PageInfo();
            page.setUrl(curURL.getURL().toLowerCase());
            page.setAccessTime(new Date().getTime());
            // at.chille.crawler.database.model.Header header = new
            // at.chille.crawler.database.model.Header();
            // header.setName("HTTP-Status-Code");
            // header.setValue(String.valueOf(statusCode));
            // page.addHeader(header);
            hostInfo.getTodoUrls().remove(
                curURL.getURL().toLowerCase());
            hostInfo.addPage(page);

            // Store to database
            hostInfo = DatabaseManager.getInstance().saveHostInfo(
                hostInfo);
            DatabaseManager.getInstance().getHostLock(fullDomain)
                .unlock();

          }
        }
        else if (fetchResult.getStatusCode() == CustomFetchStatus.PageTooBig)
        {
          logger.info("Skipping a page which was bigger than max allowed size: "
              + curURL.getURL());
        }
        return;
      }

      if (!curURL.getURL().equals(fetchResult.getFetchedUrl()))
      {
        if (docIdServer.isSeenBefore(fetchResult.getFetchedUrl()))
        {
          // Redirect page is already seen
          return;
        }
        curURL.setURL(fetchResult.getFetchedUrl());
        curURL.setDocid(docIdServer.getNewDocID(fetchResult
            .getFetchedUrl()));
      }

      Page page = new Page(curURL);
      int docid = curURL.getDocid();

      if (!fetchResult.fetchContent(page))
      {
        onContentFetchError(curURL);
        return;
      }

      if (!parser.parse(page, curURL.getURL()))
      {
        onParseError(curURL);
        return;
      }

      ParseData parseData = page.getParseData();
      if (parseData instanceof HtmlParseData)
      {
        HtmlParseData htmlParseData = (HtmlParseData) parseData;

        List<WebURL> toSchedule = new ArrayList<WebURL>();
        int maxCrawlDepth = myController.getConfig()
            .getMaxDepthOfCrawling();
        for (WebURL webURL : htmlParseData.getOutgoingUrls())
        {

          // TODO: add urls with ascending path (remove folder)
          // www.google.at/a/b/c/d/
          // www.google.at/a/b/c/
          // www.google.at/a/b/
          // www.google.at/a/
          // www.google.at/

          // always try https at least once
          // if(didnt *schedule* https yet for this domain) try https
          // also
          WebURL httpsURL = getHttpsURL(webURL);
          if (httpsURL != null)
          {
            httpsURL.setParentDocid(docid);
            httpsURL.setParentUrl(curURL.getURL());
            int newdocid = docIdServer.getDocId(httpsURL.getURL());
            if (newdocid <= 0)
            {
              httpsURL.setDepth((short) (curURL.getDepth() + 1));
              httpsURL.setDocid(-1);
              httpsURL.setPriority(this.PRIORITY_INSPECT_HTTPS);
              if (maxCrawlDepth == -1
                  || httpsURL.getDepth() < maxCrawlDepth)
              {
                if (shouldVisit(httpsURL)
                    && robotstxtServer.allows(httpsURL))
                {
                  // System.out.println("Adding additional 4 "
                  // + httpsURL.getURL());
                  httpsURL.setDocid(docIdServer
                      .getNewDocID(httpsURL.getURL()));
                  toSchedule.add(httpsURL);

                  // System.out.println(" + "+
                  // httpsURL.getURL());
                }
                // else if(!robotstxtServer.allows(httpsURL))
                {
                  // System.out.println(" - "+
                  // httpsURL.getURL() + " (robots.txt)");
                }
                // else
                {
                  // System.out.println(" - "+
                  // httpsURL.getURL() + " (shouldVisit)");
                }
              }
            }
          }
          // end of https schedule

          webURL.setParentDocid(docid);
          webURL.setParentUrl(curURL.getURL());
          int newdocid = docIdServer.getDocId(webURL.getURL());
          if (newdocid > 0)
          {
            // This is not the first time that this Url is
            // visited. So, we set the depth to a negative
            // number.
            webURL.setDepth((short) -1);
            webURL.setDocid(newdocid);
            // System.out.println(" - "+ webURL.getURL() +
            // " (newdocid > 0)");
          }
          else
          {
            webURL.setDocid(-1);
            webURL.setDepth((short) (curURL.getDepth() + 1));
            webURL.setPriority(this.PRIORITY_INSPECT_HTTP);
            if (maxCrawlDepth == -1
                || curURL.getDepth() < maxCrawlDepth)
            {
              if (shouldVisit(webURL)
                  && robotstxtServer.allows(webURL))
              {
                webURL.setDocid(docIdServer.getNewDocID(webURL
                    .getURL()));
                toSchedule.add(webURL);
                // System.out.println(" + "+ webURL.getURL());
              }
              // else if(!robotstxtServer.allows(webURL))
              {
                // System.out.println(" - "+ webURL.getURL() +
                // " (robots.txt)");
              }
              // else
              {
                // System.out.println(" - "+ webURL.getURL() +
                // " (shouldVisit)");
              }
            }
            else
            {
              // System.out.println(" - "+ webURL.getURL() +
              // " (Crawl depth)");
            }
          }
        }
        frontier.scheduleAll(toSchedule);
      }
      try
      {
        visit(page);
      }
      catch (Exception e)
      {
        logger.error("Exception while running the visit method. Message: '"
            + e.getMessage() + "' at " + e.getStackTrace()[0]);
      }

    }
    catch (Exception e)
    {
      logger.error(e.getMessage() + ", while processing: "
          + curURL.getURL());
    }
    finally
    {
      if (fetchResult != null)
      {
        fetchResult.discardContentIfNotConsumed();
      }
    }
  }

  /**
   * Returns the same URL as given, but using the HTTPS-Protocol. Returns null if the URL is already
   * using the HTTPS Protocol.
   * 
   * @param webURL
   *          http or https URL
   * @return https Url or null
   */
  private WebURL getHttpsURL(WebURL webURL)
  {
    if (webURL.getURL().startsWith("http://"))
    {
      WebURL newWebURL = new WebURL();
      newWebURL.setURL("https://" + webURL.getURL().substring(7));
      return newWebURL;
    }
    else if (webURL.getURL().startsWith("https://"))
    {
      return null;
    }
    logger.error("-- UNKNOWN PROTOCOL : " + webURL.getURL());
    return null;
  }

  @Override
  public void visit(Page page)
  {
    WebURL webUrl = page.getWebURL();

    // int docid = webUrl.getDocid();
    String url = webUrl.getURL().toLowerCase();
    // String domain = webUrl.getDomain();
    // String path = webUrl.getPath();
    // String subDomain = webUrl.getSubDomain();
    // String parentUrl = webUrl.getParentUrl();
    // String anchor = webUrl.getAnchor();

    String fullDomain = DatabaseManager.getFullDomain(webUrl);

    PageInfo pageInfo = new PageInfo();
    pageInfo.setUrl(url);

    DatabaseManager.getInstance().getHostLock(fullDomain).lock();
    HostInfo hostInfo = DatabaseManager.getInstance().getHostInfo(
        fullDomain);
    if (hostInfo == null)
    {
      hostInfo = new HostInfo();
      hostInfo.setHostName(fullDomain);
      DatabaseManager.getInstance().addHostInfo(hostInfo);
      // hostInfo.getTodoUrls().add(webUrl.getURL());
    }

    int visitedPages = this.countSimilarURLs(hostInfo.getPages().keySet(), url);
    if (visitedPages > 1) // abort, not interesting any more
    {
      logger.debug("Already visited several pages of this webserver: '" + url + "'. Aborting.");
      DatabaseManager.getInstance().getHostLock(fullDomain).unlock();
      return;
    }

    hostInfo.addPage(pageInfo);

    // System.out.println(domain+" "+ subDomain + " "+ path + " ");
    // *
    // System.out.println("Docid: " + docid);
    logger.debug("  Domain: '" + fullDomain + "'\tURL: " + url);
    // System.out.println("Domain: '" + domain + "'");
    // System.out.println("Sub-domain: '" + subDomain + "'");
    // System.out.println("Path: '" + path + "'");
    // System.out.println("Parent page: " + parentUrl);
    // System.out.println("Anchor text: " + anchor);

    if (page.getParseData() instanceof HtmlParseData)
    {
      HtmlParseData htmlParseData = (HtmlParseData) page.getParseData();
      // String text = htmlParseData.getText();
      String html = htmlParseData.getHtml().toLowerCase();
      Metadata meta = htmlParseData.getMetadata();

      for (Map.Entry<String, String> pair : detectHTML.entrySet())
      {
        if (html.contains(pair.getKey()))
        {
          System.out.println("Detected: " + pair.getValue());
          at.chille.crawler.database.model.Header headerDB = new at.chille.crawler.database.model.Header();
          headerDB.setName("Skript");
          headerDB.setValue(pair.getValue());
          pageInfo.addHeader(headerDB);
        }
      }

      String generator = meta.get("generator");
      if (generator != null)
      {
        System.out.println("Generator: " + generator);
        at.chille.crawler.database.model.Header headerDB = new at.chille.crawler.database.model.Header();
        headerDB.setName("META/Generator");
        headerDB.setValue(generator);
        pageInfo.addHeader(headerDB);
      }

      // System.out.println("Text length: " + text.length());
      // System.out.println("Html length: " + html.length());
      // System.out.println("Number of outgoing links: " +
      // links.size());
    }

    Header[] responseHeaders = page.getFetchResponseHeaders();
    if (responseHeaders != null)
    {
      // System.out.println("Response headers:");
      for (Header header : responseHeaders)
      {
        if (!blacklistHeaders.contains(header.getName().toLowerCase()))
        {
          // if (interestingHeaders.contains(header.getName())) {
          // System.out.println("\t ! " + header.getName() + ": "
          // + header.getValue());
          at.chille.crawler.database.model.Header headerDB = new at.chille.crawler.database.model.Header();
          headerDB.setName(header.getName());
          headerDB.setValue(header.getValue());
          pageInfo.addHeader(headerDB);
        }

        else
        {
          // irrelevant headers
          // System.out.println("\t   " + header.getName() + ": "
          // +
          // header.getValue());
        }
      }
    }

    hostInfo = DatabaseManager.getInstance().saveHostInfo(hostInfo);
    DatabaseManager.getInstance().getHostLock(fullDomain).unlock();

    // System.out.println("=============================================");
    // */

  }
}
