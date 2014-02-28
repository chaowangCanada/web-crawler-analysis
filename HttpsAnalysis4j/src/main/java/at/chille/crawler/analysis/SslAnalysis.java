package at.chille.crawler.analysis;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.hibernate.Hibernate;

import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.database.repository.sslchecker.HostSslInfoRepository;

/**
 * Class for Ssl-Analysis
 * 
 * @author kwk
 * 
 */
public class SslAnalysis
{
  protected PrintStream out;
  protected String name;
  protected String description;
  protected String xmlFile = "CipherSuiteRating.xml";
  protected String plainFolder = "ssl-export";
  protected String currentFolder;
  
  protected long start = -1;
  protected long end = -1;
  
  protected boolean firstRun = true; // TODO: implement check in corresponding methods
  
  private Map<String, ArrayList<HostSslInfoWithRating>> hostSslInfoToAnalyze = null;
  private Map<String, ArrayList<HostSslInfoWithRating>> hostSslInfoSorted    = null;
  private RatingValueComparator ratingValueComparator = null;

  
  /**
   * Default Constructor.
   */
  public SslAnalysis()
  {
    out = System.out;
  }

  /**
   * Initialize Ssl-Analysis
   */
  private int init()
  {
    setHostSslInfos();
    
    if (firstRun)
      return updateCipherSuiteRating();
    
    return 0;
  }
  
  public int updateCipherSuiteRating() {
    try {
      // parse the xml-file which contains the rating for the Cipher-Suites
      File file = new File(xmlFile);
      assertTrue("Create a file CipherSuiteRating.xml first!", file.exists());
      FileInputStream streamIn    = new FileInputStream(xmlFile);
      XmlCipherSuiteParser parser = new XmlCipherSuiteParser();
      parser.parse(streamIn);
      out.println("Parsed Cipher-Suite-Rating");
    } catch (Exception e) {
      System.err.println(e.getMessage());
      e.printStackTrace();
      return -1;
    }
    
    return 0;
  }

  /**
   * Exports the results as HTML5 to the given folder.
   * 
   * @param folder
   *          folder, where we can generate files
   * @return the root file path of this analysis
   */
  public int exportToFolder()
  {
    try
    {
      createOutputFolder();
      File indexFile = new File(currentFolder, "SslAnalysis.html");
      FileWriter fw = new FileWriter(indexFile, false);
      BufferedWriter index = new BufferedWriter(fw);
      
      index.write("<!DOCTYPE html>");
      index.newLine();
      index.write("<html>");
      index.newLine();
      index.write("<head>");
      index.newLine();
      index.write("<meta charset=\"UTF-8\">");
      index.newLine();
      index.write("<title>Analysis of Ssl-Hosts</title>");
      index.newLine();
      index.write("</head>");
      index.newLine();
      
      index.write("<h1> Security-Rating of Ssl-Hosts in Austria </h1>");
      index.newLine();
      index.write("<h2> Rating of latest crawl per host s</h2>");
      index.newLine();
      index.write("</body>");
      index.newLine();
      
      index.write("<ol>");
      index.newLine();
      
      for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> e : hostSslInfoSorted.entrySet()) {
        index.write("  <li>" + e.getKey());
        index.newLine();
        index.write("    <dl> <dt>- Rating: " + e.getValue().get(0).getOverallRating() + "</dt>");
        index.newLine();
        index.write("    <dt>- More info about that host: blaa </dt> </dl>");
        index.newLine();
        index.write("  </li>");
        index.newLine();
        
      }
      
      index.write("</ol>");
      index.newLine();
      
      index.write("<body>");
      index.newLine();
      index.write("</html> ");
      
      
      /*index.write("<html><body><h1>Cookies</h1>");
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
      index.write("</body></html>");*/
      index.close();
      fw.close();
      
      hostSslInfoSorted.clear();
      out.println("Exported details: " + indexFile.getCanonicalPath());
      return 0;
    }
    catch (Exception e)
    {
      e.getMessage();
      e.printStackTrace();
      return -1;
    }
  }
  
  /**
   * Get the current Date
   * 
   * @return Date
   */
  public String getCurrentDate() {
    DateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");
    //get current date time with Date()
    Date date = new Date();
    return dateFormat.format(date);
  }
  
  /**
   * Creates the output folder for the analysis
   * 
   * @return none
   */
  public void createOutputFolder() {
    currentFolder = "./" + plainFolder + "." + getCurrentDate() + "/";
    
    File file = new File(currentFolder);
    long count = 1;
    int toRemove = 0;
    
    while (file.exists()) {
      count++;
      if (count > 2 && count < 11)
        toRemove = 3;
      else if (count >= 11 && count < 101) 
        toRemove = 4;
      // it is not very likely that more than 100 exports are created in one day
      
      currentFolder = currentFolder.substring(0, currentFolder.length()-toRemove-1);
      currentFolder += "(" + count + ")/";
      file = new File(currentFolder);
    }
    
    out.println("Folder for this report: " + currentFolder);
    file.mkdir();
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
//      Hibernate.initialize(hsi);
//      for (CipherSuite cs : hsi.getAccepted())
//        Hibernate.initialize(cs);
      
      HostSslInfoWithRating host_info_tmp = new HostSslInfoWithRating();
      host_info_tmp.setTimestamp(hsi.getTimestamp());
      host_info_tmp.setAccepted(hsi.getAccepted());
      host_info_tmp.setRejected(hsi.getRejected());
      host_info_tmp.setFailed(hsi.getFailed());
      host_info_tmp.setPreferred(hsi.getPreferred());
      host_info_tmp.setHostSslName(hsi.getHostSslName());
      
      if (hostSslInfoToAnalyze.containsKey(hsi.getHostSslName())) {
        // add to the list of the corresponding host
        hostSslInfoToAnalyze.get(hsi.getHostSslName()).add(host_info_tmp);
        // only latest crawl and therefore check if current timestamp is bigger than the one in the array
//        else if (hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).getTimestamp() < 
//            hsi.getTimestamp()) TODO: delete if no longer needed
      }
      else {// create new ArrayList
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
    if (init() != 0)
      return -1;
    
    if (hostSslInfoToAnalyze == null || hostSslInfoToAnalyze.size() == 0) {
      out.println("There are no hosts to analyze! Please check the database.");
      return -1;
    }
    
    out.println("Time for analysis! Hosts to analyze: " + hostSslInfoToAnalyze.size() + ".");
    
    // create the Security-Rating for the Cipher-Suites accepted and preferred
    long calculationCount = 0;
    try {
      //iterate over all hosts in the map
      for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> entry : hostSslInfoToAnalyze.entrySet()) {
        // iterate over all HostSslInfoWithRating in the ArrayList of every host in the map
        for (HostSslInfoWithRating hsiwr : entry.getValue()) {
          // get the Cipher-Rating for accepted and store it in HostSslInfoWithRating
          for (CipherSuite cs : hsiwr.getAccepted()) {
            hsiwr.addSslRatingToSecurityRatingsAccepted(CipherSuiteRatingRepository.getInstance().
                getCipherRating(cs));
          }
          // get the Cipher-Rating for preferred and store it in HostSslInfoWithRating
          for (CipherSuite cs : hsiwr.getPreferred()) {
            hsiwr.addSslRatingToSecurityRatingsPreferred(CipherSuiteRatingRepository.getInstance().
                getCipherRating(cs));
          }
          // now calcualte the overall rating for every HostSslInfoWithRating per host
          calculationCount++;
          hsiwr.calculateOverallRating();
//          if (calculationCount % 600 == 0) {
//            out.println("###################Some testing output.#######################");
//            printSslRatingSet(hsiwr.getSecurityRatingsAccepted(), "AcceptedCiphers");
//            printSslRatingSet(hsiwr.getSecurityRatingsPreferred(), "PreferredCiphers");
//            out.println("##########The overall Rating for the host " + hsiwr.getHostSslName() + 
//                " is: " + hsiwr.getOverallRating()); TODO: remove if no longer needed
//          }
        }
        // sort the overall rating per host
        Collections.sort(entry.getValue(), new Comparator<HostSslInfoWithRating>() {
          @Override
          public int compare(HostSslInfoWithRating o1, HostSslInfoWithRating o2) {
            if(o1.getOverallRating() > o2.getOverallRating())
              return 1;
            else if (o1.getOverallRating() < o2.getOverallRating())
              return -1;
            else
              return 0;
          }
        });
      }
      
      // now sort the hosts in the map --> TODO: sort during insert would increase performance
      ratingValueComparator = new RatingValueComparator(hostSslInfoToAnalyze);
      hostSslInfoSorted = new TreeMap<String, ArrayList<HostSslInfoWithRating>>(ratingValueComparator);
      hostSslInfoSorted.putAll(hostSslInfoToAnalyze);
      hostSslInfoToAnalyze.clear();
      
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
    start = new Date().getTime();
    return_value = analyze();
    if (return_value == 0)
      return_value = exportToFolder();
    end = new Date().getTime();
    out.println("Execution time: " + this.getPerformance() + " ms.");
    out.println("-------------------------------------------------");
    return return_value;
  }

//  private void clearSortedMap() {
//    for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> entry : hostSslInfoToAnalyze.entrySet()) {
//      // iterate over all HostSslInfoWithRating in the ArrayList of every host in the map
//      for (HostSslInfoWithRating hsiwr : entry.getValue()) {
//        // get the Cipher-Rating for accepted and stored it in HostSslInfoWithRating
//        for (CipherSuite cs : hsiwr.getAccepted()) {
//          hsiwr.addSslRatingToSecurityRatingsAccepted(CipherSuiteRatingRepository.getInstance().
//              getCipherRating(cs));
//        }
//        // get the Cipher-Rating for preferred and stored it in HostSslInfoWithRating
//        for (CipherSuite cs : hsiwr.getPreferred()) {
//          hsiwr.addSslRatingToSecurityRatingsPreferred(CipherSuiteRatingRepository.getInstance().
//              getCipherRating(cs));
//        }
//  } TODO: remove if not needed
  
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

  public String getRelativePath(File path)
  {
    return this.getRelativePath(path, new File("./"));
  }
  
  public String getRelativePath(File path, File base)
  {
    return base.toURI().relativize(path.toURI()).getPath();
  }
}
