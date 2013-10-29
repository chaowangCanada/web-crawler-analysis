package at.chille.crawler.analysis;

import at.chille.crawler.database.model.*;
import at.chille.crawler.database.repository.*;

public class AnalysisListHosts extends Analysis
{

  public AnalysisListHosts()
  {
    super();
  }

  public AnalysisListHosts(boolean showDetails)
  {
    super(showDetails);
  }

  public AnalysisListHosts(long useCrawlingSessionID, boolean showDetails)
  {
    super(useCrawlingSessionID, showDetails);
  }

  @Override
  public void init()
  {
    this.name = "Hosts";
    this.description = "List all Hosts";
  }

  @Override
  public int analyze()
  {
    CrawlingSessionRepository csr = DatabaseManager.getInstance()
        .getCrawlingSessionRepository();

    for (CrawlingSession cs : csr.findAll())
    {
      out.println(cs.getTimeStarted() + " - " + cs.getDescription());
      long totalHosts = cs.getHosts().size();
      long totalPages = 0L;
      long totalTodo = 0L;
      long totalCerts = 0L;
      long totalHeaders = 0L;
      for (HostInfo hi : cs.getHosts().values())
      {
        totalPages += hi.getPages().size();
        totalTodo += hi.getTodoUrls().size();
        for (PageInfo pi : hi.getPages().values())
          totalHeaders += pi.getHeaders().size();
        if (hi.getCert().size() > 0)
          totalCerts++;
        if (this.showDetails)
        {
          out.println(" - " + hi.getHostName() + ": ("
              + hi.getPages().size() + "/todo:"
              + hi.getTodoUrls().size() + ")");
          if (hi.getCipherSuite() != null)
          {
            out.println("  + " + hi.getCipherSuite() + ", "
                + hi.getSslProtocol() + ", "
                + hi.getWantsClientAuth() + ", "
                + hi.getNeedsClientAuth() + ", "
                + hi.getCert().size());
          }
        }
      }
      out.println("Number of  Hosts:  " + totalHosts);
      out.println("Number of  Pages:  " + totalPages);
      out.println("Number of  TODO:   " + totalTodo);
      out.println("Number of  Certs:  " + totalCerts);
      out.println("Number of Headers: " + totalHeaders);

    }
    return 0;
  }

}
