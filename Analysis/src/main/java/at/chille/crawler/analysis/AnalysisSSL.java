package at.chille.crawler.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import at.chille.crawler.database.model.HostInfo;

public class AnalysisSSL extends Analysis
{

  public AnalysisSSL()
  {
    super();
  }

  public AnalysisSSL(boolean showDetails)
  {
    super(showDetails);
  }

  public AnalysisSSL(long useCrawlingSessionID, boolean showDetails)
  {
    super(useCrawlingSessionID, showDetails);
  }

  @Override
  public void init()
  {
    this.name = "SSL";
    this.description = "Analyze SSL Information";
  }

  protected Map<String, List<HostInfo>> issuers;
  protected Map<String, List<HostInfo>> sslProtocols;
  protected Map<String, List<HostInfo>> cipherSuites;
  protected List<HostInfo>              needsClientAuth;
  protected List<HostInfo>              wantsClientAuth;

  @Override
  public int analyze()
  {
    Collection<HostInfo> hostInfos = this.getHostsToAnalyze();
    // CrawlingSession session = selectCrawlingSession();
    issuers = new HashMap<String, List<HostInfo>>();
    sslProtocols = new HashMap<String, List<HostInfo>>();
    cipherSuites = new HashMap<String, List<HostInfo>>();
    needsClientAuth = new ArrayList<HostInfo>();
    wantsClientAuth = new ArrayList<HostInfo>();

    for (HostInfo host : hostInfos)
    {
      if (host.getSslProtocol() != null)
      {
        if (!sslProtocols.containsKey(host.getSslProtocol()))
          sslProtocols.put(host.getSslProtocol(),
              new ArrayList<HostInfo>());
        sslProtocols.get(host.getSslProtocol()).add(host);
      }
      if (host.getCipherSuite() != null)
      {
        if (!cipherSuites.containsKey(host.getCipherSuite()))
          cipherSuites.put(host.getCipherSuite(),
              new ArrayList<HostInfo>());
        cipherSuites.get(host.getCipherSuite()).add(host);
      }
      if (host.getNeedsClientAuth() != null && host.getNeedsClientAuth())
      {
        needsClientAuth.add(host);
      }
      if (host.getWantsClientAuth() != null && host.getWantsClientAuth())
      {
        wantsClientAuth.add(host);
      }

    }

    // Begin of output
    for (Map.Entry<String, List<HostInfo>> pair : sslProtocols.entrySet())
    {
      out.println("SSL-Protocol: " + pair.getKey() + " ("
          + pair.getValue().size() + ")");
      if (this.showDetails)
      {
        for (HostInfo host : pair.getValue())
        {
          out.println("  - " + host.getHostName());
        }
      }
    }
    for (Map.Entry<String, List<HostInfo>> pair : cipherSuites.entrySet())
    {
      out.println("Cipher Suite: " + pair.getKey() + " ("
          + pair.getValue().size() + ")");
      if (this.showDetails)
      {
        for (HostInfo host : pair.getValue())
        {
          out.println("  - " + host.getHostName());
        }
      }
    }

    out.println("Needs Client Auth: (" + needsClientAuth.size() + ")");
    if (this.showDetails)
    {
      for (HostInfo host : needsClientAuth)
      {
        out.println("  - " + host.getHostName());
      }
    }
    out.println("Wants Client Auth: (" + wantsClientAuth.size() + ")");
    if (this.showDetails)
    {
      for (HostInfo host : wantsClientAuth)
      {
        out.println("  - " + host.getHostName());
      }
    }
    return 0;
  }

  @Override
  public String exportToFolder(String folder)
  {
    try
    {
      File indexFile = new File(folder, "ssl.html");
      FileWriter fw = new FileWriter(indexFile, false);
      BufferedWriter index = new BufferedWriter(fw);
      index.write("<html><body><h1>SSL</h1><ul>");
      index.newLine();
      index.write("<ul>");
      index.write("<li><a href=\"#ssl_protocol\">SSL Protocols ("
          + sslProtocols.size() + ")</a></li>");
      index.write("<li><a href=\"#cipher_suite\">Cipher Suite ("
          + cipherSuites.size() + ")</a></li>");
      index.write("<li><a href=\"#needs_client_auth\">Needs Client Auth: ("
          + needsClientAuth.size() + ")</a></li>");
      index.write("<li><a href=\"#wants_client_auth\">Wants Client Auth: ("
          + wantsClientAuth.size() + ")</a></li>");
      index.write("</ul>");
      index.newLine();

      // SSL protocols Overview
      index.write("<h2 id=\"ssl_protocol\">SSL Protocols ("
          + sslProtocols.size() + ")</h2>");
      index.write("<ul>");
      for (String sslProtocol : sslProtocols.keySet())
      {
        index.write("<li><a href=\"#ssl_" + sslProtocol + "\">"
            + sslProtocol + "</a> (" + sslProtocols.get(sslProtocol).size() + ")</li>");
      }
      index.write("</ul>");
      index.newLine();

      // SSL protocols Details
      for (Map.Entry<String, List<HostInfo>> pair : sslProtocols
          .entrySet())
      {

        index.write("<h3 id=\"ssl_" + pair.getKey()
            + "\">SSL-Protocol: " + pair.getKey() + " ("
            + pair.getValue().size() + ")</h3>");
        index.write("<ul>");
        for (HostInfo host : pair.getValue())
        {
          index.write("<li><a href=\"https://" + host.getHostName() + "\">" + host.getHostName()
              + "</a></li>");
          index.newLine();
        }
        index.write("</ul>");
      }

      // Cipher suites Overview
      index.write("<h2 id=\"cipher_suite\">Cipher Suite ("
          + cipherSuites.size() + ")</h2>");
      index.write("<ul>");
      for (String cipherSuite : cipherSuites.keySet())
      {
        index.write("<li><a href=\"#cs_" + cipherSuite + "\">"
            + cipherSuite + "</a> (" + cipherSuites.get(cipherSuite).size() + ")</li>");
      }
      index.write("</ul>");
      index.newLine();

      // Cipher suites Details
      for (Map.Entry<String, List<HostInfo>> pair : cipherSuites
          .entrySet())
      {
        index.write("<h3 id=\"cs_" + pair.getKey()
            + "\">Cipher Suite: " + pair.getKey() + " ("
            + pair.getValue().size() + ")</h3>");
        index.write("<ul>");
        for (HostInfo host : pair.getValue())
        {
          index.write("<li><a href=\"https://" + host.getHostName() + "\">" + host.getHostName()
              + "</a></li>");
          index.newLine();
        }
        index.write("</ul>");
      }

      index.write("<h2 id=\"needs_client_auth\">Needs Client Auth: ("
          + needsClientAuth.size() + ")</h2><ul>");
      index.newLine();
      if (this.showDetails)
      {
        for (HostInfo host : needsClientAuth)
        {
          index.write("<li><a href=\"https://" + host.getHostName() + "\">" + host.getHostName()
              + "</a></li>");
          index.newLine();
        }
      }
      index.write("</ul>");
      index.write("<h2 id=\"wants_client_auth\">Wants Client Auth: ("
          + wantsClientAuth.size() + ")</h2><ul>");
      index.newLine();
      if (this.showDetails)
      {
        for (HostInfo host : wantsClientAuth)
        {
          index.write("<li><a href=\"https://" + host.getHostName() + "\">" + host.getHostName()
              + "</a></li>");
          index.newLine();
        }
      }
      index.write("</ul>");

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
