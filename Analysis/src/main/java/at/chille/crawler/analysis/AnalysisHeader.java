package at.chille.crawler.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import at.chille.crawler.database.model.Header;
import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.PageInfo;

public class AnalysisHeader extends Analysis
{

  public AnalysisHeader()
  {
    super();
  }

  public AnalysisHeader(boolean showDetails)
  {
    super(showDetails);
  }

  public AnalysisHeader(long useCrawlingSessionID, boolean showDetails)
  {
    super(useCrawlingSessionID, showDetails);
  }

  @Override
  public void init()
  {
    this.name = "Headers (Interactive Analysis)";
    this.description = "Interactive Header browsing";
  }

  private Map<String, Map<String, List<PageInfo>>> availableHeaders = new HashMap<String, Map<String, List<PageInfo>>>();

  @Override
  public int analyze()
  {
    Collection<HostInfo> hostInfos = this.getHostsToAnalyze();
    // CrawlingSession session = selectCrawlingSession();
    availableHeaders.clear();

    for (HostInfo host : hostInfos)
    {
      for (PageInfo page : host.getPages().values())
      {
        for (Header header : page.getHeaders())
        {
          if (!availableHeaders.containsKey(header.getName()))
          {
            availableHeaders.put(header.getName(),
                new HashMap<String, List<PageInfo>>());
          }
          Map<String, List<PageInfo>> availableValues = availableHeaders
              .get(header.getName());
          if (!availableValues.containsKey(header.getValue()))
          {
            availableValues.put(header.getValue(),
                new ArrayList<PageInfo>());
          }
          List<PageInfo> pages = availableValues.get(header
              .getValue());
          pages.add(page);
        }
      }
    }

    // Output for each Header-Key all possible Header Values
    for (Map.Entry<String, Map<String, List<PageInfo>>> availableHeader : availableHeaders
        .entrySet())
    {
      out.println(availableHeader.getKey());
      int total = 0;
      for (Map.Entry<String, List<PageInfo>> availableValue : availableHeader
          .getValue().entrySet())
      {
        total += availableValue.getValue().size();
        out.println(" -> " + availableValue.getKey() + " ("
            + availableValue.getValue().size() + ")");
        if (this.showDetails)
        {
          for (PageInfo page : availableValue.getValue())
          {
            out.println("      url: " + page.getUrl());
          }
        }
      }
      out.println("Total number of Pages with this Header-Name: " + total);
    }

    return 0;
  }

  @Override
  public String exportToFolder(String folder)
  {
    String style = "<link rel=\"stylesheet\" href=\"../style.css\" />";
    try
    {
      File indexFile = new File(folder, "header.html");
      FileWriter fw = new FileWriter(indexFile, false);
      BufferedWriter index = new BufferedWriter(fw);
      index.write("<html><body><h1>Headers &amp; Co</h1><ul>");
      index.newLine();
      for (Map.Entry<String, Map<String, List<PageInfo>>> availableHeader : availableHeaders
          .entrySet())
      {
        File detailFile = new File(folder, "header_"
            + availableHeader.getKey().replace("/", "-") + ".html");

        FileWriter fw2 = new FileWriter(detailFile, false);
        BufferedWriter detail = new BufferedWriter(fw2);
        detail.write("<html><head>" + style + "</head><body>");
        detail.newLine();
        detail.write("<h1>Header: " + availableHeader.getKey() + "</h1>");
        detail.newLine();
        int total = 0;
        for (Map.Entry<String, List<PageInfo>> availableValue : availableHeader
            .getValue().entrySet())
        {
          total += availableValue.getValue().size();
          detail.write("<span class=\"value\"><h2>" + availableValue.getKey() + " ("
              + availableValue.getValue().size() + ")</h2><ul>");
          detail.newLine();
          for (PageInfo page : availableValue.getValue())
          {
            detail.write("<li>" + page.getUrl() + "</li>");
            detail.newLine();
          }
          detail.write("</ul></span>");
        }
        detail.newLine();
        detail.write("Total values for this header: " + total);
        detail.newLine();
        detail.write("</body></html>");
        detail.close();
        fw2.close();

        index.write("<li><a href=\"" + this.getRelativePath(detailFile, indexFile)
            + "\">" + availableHeader.getKey() + "</a> (" + total
            + ")</li>");
        index.newLine();
      }

      index.write("</ul></body></html>");
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
