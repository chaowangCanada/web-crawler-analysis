package at.chille.crawler.analysis;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Collection;
import java.util.Date;

import at.chille.crawler.database.model.CrawlingSession;
import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.repository.CrawlingSessionRepository;

/**
 * Abstract class for Analysis-Methods
 * 
 * @author chille
 * 
 */
public abstract class Analysis
{
  protected String               name;
  protected String               description;
  protected long                 start             = -1;
  protected long                 end               = -1;
  protected PrintStream          out;
  public long                    useCrawlingSessionID;
  protected boolean              showDetails;
  protected Collection<HostInfo> hostInfoToAnalyze = null;

  /**
   * Default Constructor: ask for Crawling-Session-ID if there are more than one and show details.
   */
  public Analysis()
  {
    this(-1L, true);
  }

  /**
   * ask for Crawling-Session-ID if there are more than one
   * 
   * @param showDetails
   *          true if details for different analysis should be shown in System.out
   */
  public Analysis(boolean showDetails)
  {
    this(-1L, showDetails);
  }

  /**
   * 
   * @param useCrawlingSessionID
   *          the session ID to analyze or -1 to ask the user if there are more than one
   * @param showDetails
   *          true if details for different analysis should be shown in System.out
   */
  public Analysis(long useCrawlingSessionID, boolean showDetails)
  {
    this.useCrawlingSessionID = useCrawlingSessionID;
    name = "[not set]";
    description = "";
    out = System.out;
    this.showDetails = showDetails;
    init();
  }

  /**
   * Please override if necessary. Should be called before analyze()
   */
  protected void init()
  {

  }

  /**
   * Exports the results as HTML to the given folder. Override this!
   * 
   * @param folder
   *          folder, where we can generate files
   * @return the root file path of this analysis
   */
  public String exportToFolder(String folder)
  {
    return null;
  }

  public void setHostsToAnalyze(Collection<HostInfo> hostInfoToAnalyze)
  {
    this.hostInfoToAnalyze = hostInfoToAnalyze;
  }

  protected Collection<HostInfo> getHostsToAnalyze()
  {
    if (this.hostInfoToAnalyze == null)
    {
      CrawlingSession cs = selectCrawlingSession();
      this.hostInfoToAnalyze = cs.getHosts().values();
    }
    return this.hostInfoToAnalyze;
  }

  /**
   * Internal method to select a crawling Session. Loads CrawlingSession from Database.
   * 
   * @return a loaded CrawlingSession to analyze
   */
  private CrawlingSession selectCrawlingSession()
  {
    CrawlingSessionRepository csr = DatabaseManager.getInstance()
        .getCrawlingSessionRepository();
    long size = csr.count();

    // Behavior is clear:
    if (size == 0)
      return null;
    if (size == 1)
      return csr.findAll().iterator().next();
    if (useCrawlingSessionID != -1)
      return csr.findOne(useCrawlingSessionID);

    // Ask user:
    for (CrawlingSession cs : csr.findAll())
    {
      System.out.println(cs.getId() + ". " + cs.getTimeStarted() + " "
          + cs.getDescription());
    }
    BufferedReader console = new BufferedReader(new InputStreamReader(
        System.in));
    long wahl = -1;
    CrawlingSession cs = null;
    while (cs == null)
    {
      try
      {
        wahl = Long.parseLong(console.readLine());
        cs = csr.findOne(wahl);
      }
      catch (Exception ex)
      {
      }
    }

    return cs;
  }

  /**
   * Override this!
   */
  public abstract int analyze();

  /**
   * Starts the analysis and prints a small runtime-statistic.
   * 
   * @return
   */
  public final int start()
  {
    int return_value = 0;
    out.println("-------------------------------------------------");
    out.println("Name:        " + this.getName());
    out.println("Description: " + this.getDescription());
    start = new Date().getTime();
    return_value = analyze();
    end = new Date().getTime();
    out.println("Execution time: " + this.getPerformance() + " ms.");
    return return_value;
  }

  /**
   * Returns the runtime in milliseconds of the analysis called using start().
   * 
   * @return
   */
  public long getPerformance()
  {
    if (end == 0)
      return -1;
    return end - start;
  }

  /**
   * Returns the name of the Analysis (e.g. for Menu)
   * 
   * @return
   */
  public String getName()
  {
    return name;
  }

  /**
   * Returns a more detailed description of the Analysis
   * 
   * @return
   */
  public String getDescription()
  {
    return description;
  }

  /**
   * Sets an alternative output stream instead of System.out
   * 
   * @param output
   */
  public void setOutputStream(PrintStream output)
  {
    this.out = output;
  }

  public boolean isShowDetails()
  {
    return showDetails;
  }

  public void setShowDetails(boolean showDetails)
  {
    this.showDetails = showDetails;
  }

  public String getRelativePath(File path)
  {
    return this.getRelativePath(path, new File("./"));
  }
  
  public String getRelativePath(File path, File base)
  {
    return base.toURI().relativize(path.toURI()).getPath();
  }
}
