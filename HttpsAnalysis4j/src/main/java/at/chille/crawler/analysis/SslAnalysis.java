package at.chille.crawler.analysis;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.database.repository.sslchecker.HostSslInfoRepository;

/**
 * Class for Ssl-Analysis
 * 
 * @author acn
 * 
 */
public class SslAnalysis
{
  
  
  protected PrintStream out;
  protected String name;
  protected String description;
  protected String xmlFile = "CipherSuiteRating.xml";
  protected long   start         = -1;
  protected long   end           = -1;
  private boolean  showDetails;
  private boolean  all_crawls;
  
  private Map<String, ArrayList<HostSslInfoWithRating>> hostSslInfoToAnalyze = null;

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
      name = "Analyse only latest Crawl per Host";
    description = "";
    out = System.out;
    this.showDetails = showDetails;
    this.all_crawls  = all_crawls;
  }

  /**
   * Initialize Ssl-Analysis
   */
  private void init()
  {
    setHostSslInfos();
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
    /*try
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
    }*/
    return null;
  }
  
  /**
   * initializes allHostSslInfoToAnalyze
   * 
   * @return none
   */
  protected void setHostSslInfos() 
  {
    HostSslInfoRepository hsir = DatabaseManager.getInstance().getHostSSLInfoRepository();
    long count = hsir.count();
    
    if (count == 0)
    {
      hostSslInfoToAnalyze = null;
      return;
    }
    
    hostSslInfoToAnalyze = new HashMap<String, ArrayList<HostSslInfoWithRating>>();
    
    for (HostSslInfo hsi : hsir.findAll())
    {
      HostSslInfoWithRating host_info_tmp = new HostSslInfoWithRating();
      host_info_tmp.setTimestamp(hsi.getTimestamp());
      host_info_tmp.setAccepted(hsi.getAccepted());
      host_info_tmp.setRejected(hsi.getRejected());
      host_info_tmp.setFailed(hsi.getFailed());
      host_info_tmp.setPreferred(hsi.getPreferred());
      host_info_tmp.setHostSslName(hsi.getHostSslName());
      
      if (hostSslInfoToAnalyze.containsKey(hsi.getHostSslName()))
      {
        if (this.all_crawls)
        {
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).add(host_info_tmp);
        }
        // only latest crawl and therefore check if current timestamp is bigger than the one in the array
        else if (hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).getTimestamp() < 
            hsi.getTimestamp())
        {
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).setTimestamp(hsi.getTimestamp());
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).setAccepted(hsi.getAccepted());
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).setRejected(hsi.getRejected());
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).setFailed(hsi.getFailed());
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).setPreferred(hsi.getPreferred());
        }
      }
      else // create new ArrayList
      {
        ArrayList<HostSslInfoWithRating> list_tmp = new ArrayList<HostSslInfoWithRating>();
        list_tmp.add(host_info_tmp);
        hostSslInfoToAnalyze.put(hsi.getHostSslName(), list_tmp);
      }
    }
  }
  /**
   * Method for analyzing
   */
  public int analyze()
  {
    init();
    out.println("Time for analysis! Hosts to analyze: " + hostSslInfoToAnalyze.size() + ".");
    
    // create the Security-Rating for the Cipher-Suites accepted and preferred
    long calculationCount = 0;
    try {
      // at first the xml-file is parsed
      File file = new File(xmlFile);
      assertTrue("Create a file CipherSuiteRating.xml first!", file.exists());
      FileInputStream streamIn    = new FileInputStream(xmlFile);
      XmlCipherSuiteParser parser = new XmlCipherSuiteParser();
      parser.parse(streamIn);
      
      //iterate over all hosts in the map
      for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> entry : hostSslInfoToAnalyze.entrySet()) {
        // iterate over all HostSslInfoWithRating in the ArrayList of every host in the map
        for (HostSslInfoWithRating hsiwr : entry.getValue()) {
          // get the Cipher-Rating for accepted and stored it in HostSslInfoWithRating
          for (CipherSuite cs : hsiwr.getAccepted()) {
            hsiwr.addSslRatingToSecurityRatingsAccepted(CipherSuiteRatingRepository.getInstance().
                getCipherRating(cs));
          }
          // get the Cipher-Rating for preferred and stored it in HostSslInfoWithRating
          for (CipherSuite cs : hsiwr.getPreferred()) {
            out.println("preferred!!");
            hsiwr.addSslRatingToSecurityRatingsPreferred(CipherSuiteRatingRepository.getInstance().
                getCipherRating(cs));
          }
          // now calcualte the overall rating for every HostSslInfoWithRating per host
          calculationCount++;
          hsiwr.calculateOverallRating();
          //if (calculationCount % 600 == 0) {
            //out.println("###################Some testing output.#######################");
            //printSslRatingSet(hsiwr.getSecurityRatingsAccepted(), "AcceptedCiphers");
            printSslRatingSet(hsiwr.getSecurityRatingsPreferred(), "PreferredCiphers");
            //out.println("##########The overall Rating for the host " + hsiwr.getHostSslName() + 
            //    " is: " + hsiwr.getOverallRating());
          //}
        }
      }
    } catch (Exception e) {
        System.out.println(e.getMessage());
        e.printStackTrace();
        return -1;
    }
    
    out.println("Finished analysis! Calculated " + calculationCount + " times an overall rating.");
    return 0;
  }
  
  private void printSslRatingSet(Set<SslRating> s, String typeOfSet) {
    Iterator<SslRating> it = s.iterator();
    while (it.hasNext()) {
      SslRating r = it.next();
      out.println("Output of " + typeOfSet + ": Value is " + r.getValue() + ", "
          + "CipherSuite is " + r.getCipherSuite().getCipherSuite() + " and Description is: " + r.getDescription());
    }
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
