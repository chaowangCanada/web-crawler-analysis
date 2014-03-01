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
  private PrintStream out;
  
  private String plainFolder = "ssl-export";
  private String currentFolder;
  
  private long start = -1;
  private long end = -1;
  
  private boolean firstRun = true; // TODO: implement check in corresponding methods --> remove if not necessary
  
  private Map<String, ArrayList<HostSslInfoWithRating>> hostSslInfoToAnalyze = null;
  private Map<String, ArrayList<HostSslInfoWithRating>> hostSslInfoSorted    = null;
  private RatingValueComparator ratingValueComparator = null;

  //-----------------------------CONSTANTS-----------------------------
  private String xmlFileCipherSuiteRating = "CipherSuiteRating.xml";
  private String reportHTMLFileName = "SslAnalysis.html";
  private String reportCSSFileName = "SslAnalysisStyle.css";
  //-------------------------------------------------------------------
  
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
      File file = new File(xmlFileCipherSuiteRating);
      assertTrue("Create a file CipherSuiteRating.xml first!", file.exists());
      FileInputStream streamIn    = new FileInputStream(xmlFileCipherSuiteRating);
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
      File indexFile = new File(currentFolder, reportHTMLFileName);
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
      index.write("<link href=\"" + reportCSSFileName + "\" rel=\"stylesheet\" type=\"text/css\" />");
      index.newLine(); 
      index.write("</head>");
      index.newLine();
      
      index.write("<header>");
      index.newLine();
      index.write("<h1> Security-Rating of Ssl-Hosts in Austria </h1>");
      index.newLine();
      index.write("<h2> Rating of latest crawl per hosts </h2>");
      index.newLine();
      index.write("</header>");
      index.newLine();
      index.write("</body>");
      index.newLine();
      
      index.write("<ol class=\"top-3-hosts\">");
      index.newLine();
      
      long top3Counter = 0;
      long top3Actual  = 3;
      double previousRating = 0;
      double actualRating;
      
      // check for same values after the third rating
      for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> e : hostSslInfoSorted.entrySet()) {
        top3Counter++;
        actualRating   = e.getValue().get(0).getOverallRating();
        if (top3Counter == top3Actual+1) {
          if (previousRating == actualRating)
            top3Actual++;
          else
            break;
        }
        previousRating = e.getValue().get(0).getOverallRating();
      }
      
      top3Counter = 0;
      // write list
      for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> e : hostSslInfoSorted.entrySet()) {
        index.write("  <li>" + e.getKey());
        index.newLine();
        index.write("    <dl> <dt>- Rating: " + e.getValue().get(0).getOverallRating() + "</dt>");
        index.newLine();
        index.write("    <dt>- More info about that host: blaa </dt> </dl>");
        index.newLine();
        index.write("  </li>");
        index.newLine();
        
        if (top3Counter != top3Actual+1) {
          top3Counter++;
          if (top3Counter == top3Actual) {
            index.write("</ol>");
            index.newLine();
            index.write("<ol class=\"other-hosts\" start=\"4\">");
            index.newLine();
          }
        }
        
        
      }
      
      if (top3Counter == top3Actual+1) {
        index.write("</ol>");
        index.newLine();
      }
      
      index.write("<body>");
      index.newLine();
      index.write("</html> ");
      
      index.close();
      fw.close();
      
      createCssFile();
      
      hostSslInfoSorted.clear();
      out.println("Exported details: " + indexFile.getCanonicalPath());
    }
    catch (Exception e)
    {
      e.getMessage();
      e.printStackTrace();
      return -1;
    }
    
    
    return 0;
  }
  
  private void createCssFile() throws Exception {
    File indexFile = new File(currentFolder, reportCSSFileName);
    FileWriter fw = new FileWriter(indexFile, false);
    BufferedWriter index = new BufferedWriter(fw);
    
    index.write("html { \n  font-family: Sans-Serif; }");
    index.newLine();
    
    index.write("header {");
    index.newLine();
    index.write("  background: linear-gradient(black, red, red, white, red, red, black); ");
    index.write("text-align:center; color: black;}");
    index.newLine();
    
    index.write("body { \n  background: steelblue; }");
    index.newLine();
    
    index.write("ol.top-3-hosts { \n  color: white; }");
    index.newLine();
    
    index.write("ol.other-hosts{");
    index.newLine();
    index.write("  display: block; background: white; }");
    index.newLine();
    index.write("ol.other-hosts li > dl {");
    index.newLine();
    index.write("  display: none; }");
    index.newLine();
    index.write("ol.other-hosts li:hover > dl {");
    index.newLine();
    index.write("  display: block; }");
    index.newLine();
    
  
  /*.rectangle-list a{
    position: relative;
    display: block;
    padding: .4em .4em .4em .8em;
    *padding: .4em;
    margin: .5em 0 .5em 2.5em;
    background: #ddd;
    color: #444;
    text-decoration: none;
    transition: all .3s ease-out;   
}

.rectangle-list a:hover{
    background: #eee;
}   

.rectangle-list a:before{
    content: counter(li);
    counter-increment: li;
    position: absolute; 
    left: -2.5em;
    top: 50%;
    margin-top: -1em;
    background: #fa8072;
    height: 2em;
    width: 2em;
    line-height: 2em;
    text-align: center;
    font-weight: bold;
}

.rectangle-list a:after{
    position: absolute; 
    content: '';
    border: .5em solid transparent;
    left: -1em;
    top: 50%;
    margin-top: -.5em;
    transition: all .3s ease-out;               
}

.rectangle-list a:hover:after{
    left: -.5em;
    border-left-color: #fa8072;             
}  */
    
    index.close();
    fw.close();
//    p
//    {
//    font-family:"Times New Roman";
//    font-size:20px;
//    }
  }
  
  /**
   * Get the current Date
   * 
   * @return Date
   */
  private String getCurrentDate() {
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
  private void createOutputFolder() {
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
