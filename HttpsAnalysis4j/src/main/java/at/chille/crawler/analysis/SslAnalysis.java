package at.chille.crawler.analysis;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.net.ssl.SSLSocket;

import at.chille.crawler.database.model.CrawlingSession;
import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.database.repository.CrawlingSessionRepository;
import at.chille.crawler.database.repository.sslchecker.HostSslInfoRepository;

/**
 * Class for Ssl-Analysis
 * 
 * @author acn
 * 
 */
public class SslAnalysis
{
  
  protected String      name;
  protected String      description;
  protected long        start         = -1;
  protected long        end           = -1;
  protected PrintStream out;
  private boolean     showDetails;
  private boolean     all_crawls;
  
  private Map<String, ArrayList<HostSslInfoWithRating>> allHostSslInfoToAnalyze    = null;
  private Map<String, HostSslInfoWithRating>            latestHostSslInfoToAnalyze = null;

  /**
   * Default Constructor: show details.
   */
  public SslAnalysis(boolean all_crawls)
  {
    this(true, all_crawls);
  }

  /**
   * @param showDetails
   *          true if details for different analysis should be shown in System.out
   */
  public SslAnalysis(boolean showDetails, boolean all_crawls)
  {
    if (all_crawls)
      name = "Analyse all Crawls";
    else 
      name = "Analyse only latest Crawl of Hosts";
    description = "";
    out = System.out;
    this.showDetails = showDetails;
    this.all_crawls  = all_crawls;
  }

  /**
   * Initialize Ssl-Analysis
   */
  private void init(boolean all_crawls)
  {
    if (all_crawls)
      setAllHostSslInfos();
    else
      setLatestCrawlHostSslInfos();
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

//  public void setHostsToAnalyze(Collection<HostInfo> hostInfoToAnalyze)
//  {
//    this.hostInfoToAnalyze = hostInfoToAnalyze;
//  }

//  protected Collection<HostInfo> getHostSslInfosToAnalyze()
//  {
//    if (this.hostSslInfoToAnalyze == null)
//    {
//      CrawlingSession cs = selectCrawlingSession();
//      this.hostInfoToAnalyze = cs.getHosts().values();
//    }
//    return this.hostInfoToAnalyze;
//  }
  
    
  
  /**
   * initializes allHostSslInfoToAnalyze
   * 
   * @return none
   */
  protected void setAllHostSslInfos() 
  {
    HostSslInfoRepository hsir = DatabaseManager.getInstance()
        .getHostSSLInfoRepository();
    long count = hsir.count();
    
    if (count == 0)
    {
      allHostSslInfoToAnalyze = null;
      return;
    }
    
    allHostSslInfoToAnalyze = new HashMap<String, ArrayList<HostSslInfoWithRating>>();
    
    for (HostSslInfo hsi : hsir.findAll())
    {
      HostSslInfoWithRating host_info_tmp = new HostSslInfoWithRating();
      host_info_tmp.setTimestamp(hsi.getTimestamp());
      host_info_tmp.setAccepted(hsi.getAccepted());
      host_info_tmp.setRejected(hsi.getRejected());
      host_info_tmp.setFailed(hsi.getFailed());
      host_info_tmp.setPreferred(hsi.getPreferred());
      host_info_tmp.setHostSslName(hsi.getHostSslName());
      
      if (allHostSslInfoToAnalyze.containsKey(hsi.getHostSslName()))
      {
        allHostSslInfoToAnalyze.get(hsi.getHostSslName()).add(host_info_tmp);
      }
      else // create new ArrayList
      {
        ArrayList<HostSslInfoWithRating> list_tmp = new ArrayList<HostSslInfoWithRating>();
        list_tmp.add(host_info_tmp);
        allHostSslInfoToAnalyze.put(hsi.getHostSslName(), list_tmp);
      }
    }
  }
  
  /**
   * initializes latestHostSslInfoToAnalyze
   * 
   * @return none
   */
  protected void setLatestCrawlHostSslInfos()
  {
  
    HostSslInfoRepository hsir = DatabaseManager.getInstance()
        .getHostSSLInfoRepository();
    long count = hsir.count();
    
    if (count == 0)
    {
      latestHostSslInfoToAnalyze = null;
      return;
    }
    
    latestHostSslInfoToAnalyze = new HashMap<String, HostSslInfoWithRating>();
    
    for (HostSslInfo hsi : hsir.findAll())
    {
      
      if(latestHostSslInfoToAnalyze.containsKey(hsi.getHostSslName()))
      {
        // check if timestamp is newer
        if (latestHostSslInfoToAnalyze.get(hsi.getHostSslName()).getTimestamp() < 
            hsi.getTimestamp())
        {
          latestHostSslInfoToAnalyze.get(hsi.getHostSslName())
              .setTimestamp(hsi.getTimestamp());
          latestHostSslInfoToAnalyze.get(hsi.getHostSslName())
              .setAccepted(hsi.getAccepted());
          latestHostSslInfoToAnalyze.get(hsi.getHostSslName())
            .setRejected(hsi.getRejected());
          latestHostSslInfoToAnalyze.get(hsi.getHostSslName())
            .setFailed(hsi.getFailed());
          latestHostSslInfoToAnalyze.get(hsi.getHostSslName())
            .setPreferred(hsi.getPreferred());
        }
      }
      else // create new entry
      {
        HostSslInfoWithRating host_info_tmp = new HostSslInfoWithRating();
        host_info_tmp.setTimestamp(hsi.getTimestamp());
        host_info_tmp.setAccepted(hsi.getAccepted());
        host_info_tmp.setRejected(hsi.getRejected());
        host_info_tmp.setFailed(hsi.getFailed());
        host_info_tmp.setPreferred(hsi.getPreferred());
        host_info_tmp.setHostSslName(hsi.getHostSslName());
        
        latestHostSslInfoToAnalyze.put(hsi.getHostSslName(), host_info_tmp);
      }
    }
  }

  /**
   * Method for analyzing
   */
  public int analyze()
  {
    init(all_crawls);
    
    out.println("time for analysis!");
    if (all_crawls)
      out.println("hosts in allHostSslInfo: " + allHostSslInfoToAnalyze.size());
    else
      out.println("hosts in latestHostSslInfo: " + latestHostSslInfoToAnalyze.size());
    
    return 0;
  }

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
