package at.chille.crawler.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import at.chille.crawler.database.model.Header;
import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.PageInfo;

public class AnalysisCookies extends Analysis
{

  public AnalysisCookies()
  {
    super();
  }

  public AnalysisCookies(boolean showDetails)
  {
    super(showDetails);
  }

  public AnalysisCookies(long useCrawlingSessionID, boolean showDetails)
  {
    super(useCrawlingSessionID, showDetails);
  }

  @Override
  public void init()
  {
    this.name = "Cookies";
    this.description = "";
  }

  List<AbstractMap.SimpleEntry<PageInfo, String>> cookies;
  List<AbstractMap.SimpleEntry<PageInfo, String>> httpsCookiesNotSecure;
  List<AbstractMap.SimpleEntry<PageInfo, String>> usingHttpOnly;
  long                                            httpsCookiesCount;

  protected void checkCookie(String cookie, PageInfo page)
  {
    cookies.add(new AbstractMap.SimpleEntry<PageInfo, String>(page, cookie));
    if (page.getUrl().toLowerCase().startsWith("https://"))
    {
      httpsCookiesCount++;
      if (!cookie.toLowerCase().contains("secure"))
      {
        httpsCookiesNotSecure.add(new AbstractMap.SimpleEntry<PageInfo, String>(page, cookie));
      }
    }
    if (cookie.toLowerCase().contains("httponly"))
    {
      usingHttpOnly.add(new AbstractMap.SimpleEntry<PageInfo, String>(page, cookie));
    }
  }

  @Override
  public int analyze()
  {
    Collection<HostInfo> hostInfos = this.getHostsToAnalyze();
    // CrawlingSession session = selectCrawlingSession();
    cookies = new ArrayList<AbstractMap.SimpleEntry<PageInfo, String>>();
    httpsCookiesNotSecure = new ArrayList<AbstractMap.SimpleEntry<PageInfo, String>>();
    usingHttpOnly = new ArrayList<AbstractMap.SimpleEntry<PageInfo, String>>();
    httpsCookiesCount = 0;

    for (HostInfo host : hostInfos)
    {
      for (PageInfo page : host.getPages().values())
      {
        for (Header header : page.getHeaders())
        {
          String hn = header.getName().toLowerCase();
          if (hn.equals("set-cookie") || hn.equals("cookie") || hn.equals("set-cookie2"))
          {
            String cookie = header.getValue();
            this.checkCookie(cookie, page);
          }
        }
      }
    }

    return 0;
  }

  public void exportCookieMap(
      List<AbstractMap.SimpleEntry<PageInfo, String>> cookies,
      BufferedWriter index) throws IOException
  {
    index.write("<ul>");
    index.newLine();
    for (Map.Entry<PageInfo, String> cookie : cookies)
    {
      String url = cookie.getKey().getUrl();
      index.write("<li><a href=\"" + url + "\">" + url + "</a>: " + cookie.getValue() + "</li>");
      index.newLine();
    }
    index.write("</ul>");
    index.newLine();
  }

  @Override
  public String exportToFolder(String folder)
  {
    try
    {
      File indexFile = new File(folder, "cookies.html");
      FileWriter fw = new FileWriter(indexFile, false);
      BufferedWriter index = new BufferedWriter(fw);
      index.write("<html><body><h1>Cookies</h1>");
      index.write("<ul>");
      index.write("<li>Https Cookies without 'Secure': " + httpsCookiesNotSecure.size() + " of "
          + httpsCookiesCount + " HTTPS-Cookies</li>");
      index.write("<li>HTTPonly Cookies: " + usingHttpOnly.size() + " of total " + cookies.size()
          + " Cookies.</li>");
      index.write("</ul>");
      index.newLine();

      // HTTPS Cookies
      index.write("<h2>Insecure HTTPS Cookies (" + httpsCookiesNotSecure.size() + "/"
          + httpsCookiesCount + ")</h2>");
      index.newLine();
      this.exportCookieMap(httpsCookiesNotSecure, index);

      // HTTPonly Cookies
      index
          .write("<h2>HTTPonly Cookies (" + usingHttpOnly.size() + "/" + cookies.size() + ")</h2>");
      index.newLine();
      this.exportCookieMap(usingHttpOnly, index);

      // ALL Cookies
      index.write("<h2>All Cookies (" + cookies.size() + ")</h2>");
      this.exportCookieMap(cookies, index);
      index.write("</body></html>");
      index.close();
      fw.close();
      return indexFile.getCanonicalPath();
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null;
  }

}
