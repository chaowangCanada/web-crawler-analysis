package at.chille.crawler.analysis;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.persistence.CascadeType;
import javax.persistence.FetchType;
import javax.persistence.ManyToMany;

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
  
  private long start = -1;
  private long end = -1;
  private long hostMergeTime = 0;

  private boolean firstRun = true;
  
  private Map<String, ArrayList<HostSslInfoWithRating>> hostSslInfoToAnalyze = null;
  private Map<String, ArrayList<HostSslInfoWithRating>> hostSslInfoSorted    = null;
  private Map<String, SslRating> cipherSuitesPlain = null;
  private Map<String, SslRating> cipherSuitesSorted = null;

  //-----------------------------CONSTANTS-----------------------------
  private String plainFolder = "ssl-export";
  private String currentFolder;
  private String xmlFileCipherSuiteRating = "CipherSuiteRating.xml";
  private String reportHTMLFileName = "SslAnalysis.html";
  private String reportCSSFileName = "SslAnalysisStyle.css";
  private String hostDataFolder = "data";
  private String ciperSuiteDataName = "cipherSuiteData.html";
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
    DatabaseManager.getInstance().loadLastRecentHostSslInfos();
    setHostSslInfos();
    
    cipherSuitesPlain = new HashMap<String, SslRating>();
    
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
      index.write("  <head>");
      index.newLine();
      index.write("    <meta charset=\"UTF-8\">");
      index.newLine();
      index.write("    <title>Analysis of Ssl-Hosts</title>");
      index.newLine();
      index.write("    <link href=\"" + reportCSSFileName + "\" rel=\"stylesheet\" type=\"text/css\" />");
      index.newLine(); 
      //index.write("    <script src=\"DisplayInfo.js\" type=\"text/javascript\"></script>");
      //index.newLine();
      index.write("  </head>");
      index.newLine();
      
      index.newLine();
      index.write("  <body>");
      index.newLine();
      
      index.write("    <header>");
      index.newLine();
      index.write("      <h1> Security-Rating of Ssl-Hosts in Austria </h1>");
      index.newLine();
      index.write("      <h2> Rating of latest crawl per hosts </h2>");
      index.newLine();
      index.write("    </header>");
      index.newLine();
      
      index.write("    <div class=menu>");
      index.newLine();
      index.write("      <div class=entry><a href=\"javascript:displayDetailledInfo('"
          + hostDataFolder + "/" + ciperSuiteDataName + "');\">List of all ciphersuites</a></div>");
      index.newLine();
      index.write("    </div>");
      index.newLine();
      
      index.write("    <section>");
      index.newLine();
      index.write("      <ol class=\"top-3-hosts\">");
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
        index.write("        <li>" + e.getKey().trim());
        index.write("<dl><dt>- Rating: " + e.getValue().get(0).getOverallRating() + "</dt>");
        index.write("<dt><a href=\"javascript:displayDetailledInfo('"+hostDataFolder+"/"+e.getKey().trim()+
            ".html');\">- More info </a></dt></dl>");
        index.write("</li>");
        index.newLine();
        
        if (top3Counter != top3Actual+1) {
          top3Counter++;
          if (top3Counter == top3Actual) {
            index.write("      </ol>");
            index.newLine();
            index.write("      <ol class=\"other-hosts\" start=\"" + (top3Actual+1) + "\">");
            index.newLine();
          }
        }
        
        
      }
      
      if (top3Counter == top3Actual+1) {
        index.write("      </ol>");
        index.newLine();
      }
      
      index.write("    </section>");
      index.newLine();
      index.write("    <aside>");
      index.newLine();
      index.write("      <iframe id=\"DetailledInfo\" src=\"data/" + 
          hostSslInfoSorted.entrySet().iterator().next().getKey().trim() + ".html\"></iframe> ");
      index.newLine();
      index.write("      <script>");
      index.newLine();
      createJavascriptSection(index, "        ");
      index.write("      </script>");
      index.newLine();
      index.write("    </aside>");
      index.newLine();
      index.write("  </body>");
      index.newLine();
      index.write("</html> ");
      
      index.close();
      fw.close();
      
      createHostData();
      createCipherSuiteData();
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
  
  private void createJavascriptSection(BufferedWriter index, String indentation) throws Exception {
    index.write(indentation);
    index.write("function displayDetailledInfo(dataFile) {");
    index.newLine();
    index.write(indentation);
    index.write("  document.getElementById('DetailledInfo').setAttribute('src',dataFile);");
    index.newLine();
    index.write(indentation);
    index.write("}");
  }

  private void createCipherSuiteData() throws Exception {
    String currentHostDataFolder = currentFolder + hostDataFolder + "/";
    File file = new File(currentHostDataFolder);
    file.mkdir();
    
    File indexFile = new File(currentHostDataFolder, ciperSuiteDataName);
    FileWriter fw = new FileWriter(indexFile, false);
    BufferedWriter index = new BufferedWriter(fw);
    
    index.write("<!DOCTYPE html>");
    index.newLine();
    index.write("<html>");
    index.newLine();
    index.write("  <head>");
    index.newLine();
    index.write("    <meta charset=\"UTF-8\">");
    index.newLine();
    index.write("    <link href=\"../" + reportCSSFileName + "\" rel=\"stylesheet\" type=\"text/css\" />");
    index.newLine(); 
    index.write("  </head>");
    index.newLine();
    
    index.write("  <body>");
    index.newLine();
    
    index.write("    <div class=\"CipherSuiteData\">");
    index.newLine();
    index.write("      <div id=\"Title\" >List of all ciphersuites</div>");
    index.newLine();
    index.write("      <div id=\"Time\">" + getCurrentDate(true) + "</div>");
    index.newLine();
    
    for (Map.Entry<String, SslRating> e : cipherSuitesSorted.entrySet()) {
      index.write("      <div class=\"CipherSuite\"><div id=\"Name\">" + e.getKey() + "</div>"
          + "<div id=\"Rating\">");
      double rating = new BigDecimal(e.getValue().getValue()).setScale(2, RoundingMode.HALF_UP).
          doubleValue();
      index.write(rating + "</div>");
      index.newLine();
      index.write("        <div class=\"CipherSuiteDescription\"><div id=\"Type\">Handshake</div>"
          + "<div id=\"Content\">" + e.getValue().getDescriptionHandshake() + "</div></div>");
      index.newLine();
      index.write("        <div class=\"CipherSuiteDescription\"><div id=\"Type\">Bulk Cipher</div>"
          + "<div id=\"Content\">" + e.getValue().getDescriptionBulkCipher() + "</div></div>");
      index.newLine();
      index.write("        <div class=\"CipherSuiteDescription\"><div id=\"Type\">Hash</div>"
          + "<div id=\"Content\">" + e.getValue().getDescriptionHash() + "</div></div>");
      index.newLine();
      index.write("        <div class=\"CipherSuiteDescription\"><div id=\"Type\">TLS-Version</div>"
          + "<div id=\"Content\">" + e.getValue().getDescriptionTlsVersion() + "</div></div>");
      index.newLine();
      index.write("      </div>");
      index.newLine();
    }
    index.write("    </div>"); // CipherSuiteData
    index.newLine();
    
    index.write("  </body>");
    index.newLine();
    index.write("</html>");
    
    index.close();
    fw.close();
  }

  private void createHostData() throws Exception {
    String currentHostDataFolder = currentFolder + hostDataFolder + "/";
    File file = new File(currentHostDataFolder);
    file.mkdir();
    
    for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> host : hostSslInfoSorted.entrySet()) {
      File indexFile = new File(currentHostDataFolder, host.getKey().trim() + ".html");
      FileWriter fw = new FileWriter(indexFile, false);
      BufferedWriter index = new BufferedWriter(fw);
      
      index.write("<!DOCTYPE html>");
      index.newLine();
      index.write("<html>");
      index.newLine();
      index.write("  <head>");
      index.newLine();
      index.write("    <meta charset=\"UTF-8\">");
      index.newLine();
      index.write("    <link href=\"../" + reportCSSFileName + "\" rel=\"stylesheet\" type=\"text/css\" />");
      index.newLine(); 
      index.write("  </head>");
      index.newLine();
      
      index.write("  <body>");
      index.newLine();
      
      index.write("    <div class=\"HostSslInfo\" >");
      index.newLine();
      index.write("      <div id=\"Title\" >" + host.getKey().trim() + "</div>");
      index.newLine();
      
      for (HostSslInfoWithRating hsiwr : host.getValue()) {
        index.write("      <div class=\"Crawl\">");
        index.newLine();
        index.write("        <div id=\"Time\">" + getCrawlTime(hsiwr.getTimestamp()) + "</div>");
        index.newLine();
        index.write("        <div id=\"Rating\">");
        if (hsiwr.getOverallRating() >= 0)
          index.write(" ");
        index.write(hsiwr.getOverallRating() + "</div>");
        index.newLine();
        
        index.write("        <div class=\"CipherList\">");
        index.newLine();
        index.write("          <div id=\"Title\">Preferred</div>");
        index.newLine();
        for (SslRating sr : hsiwr.getSecurityRatingsPreferred()) {
          index.write("          <div class=\"Cipher\">");
          index.write("<div id=\"Name\">" + sr.getCipherSuite().getTlsVersion() + "__" 
              + sr.getCipherSuite().getCipherSuite().replace('-','_') + "__" 
              + sr.getCipherSuite().getBits() + "bits</div>");
          double rating = new BigDecimal(sr.getValue()).setScale(2, RoundingMode.HALF_UP).doubleValue();
          index.write("<div id=\"Rating\">");
          index.write(rating + "</div>");
          index.newLine();
          
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">Handshake</div>"
              + "<div id=\"Content\">" + sr.getDescriptionHandshake() + "</div></div>");
          index.newLine();
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">Bulk Cipher</div>"
              + "<div id=\"Content\">" + sr.getDescriptionBulkCipher() + "</div></div>");
          index.newLine();
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">Hash</div"
              + "><div id=\"Content\">" + sr.getDescriptionHash() + "</div></div>");
          index.newLine();
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">TLS-Version</div>"
              + "<div id=\"Content\">" + sr.getDescriptionTlsVersion() + "</div></div>");
          index.newLine();
          
          index.write("          </div>"); // end Cipher
          index.newLine();
        }
        index.write("        </div>"); // end CipherList
        index.newLine();
         
        index.write("        <div class=\"CipherList\">");
        index.newLine();
        index.write("          <div id=\"Title\">All supported ciphersuites</div>");
        index.newLine();
        for (SslRating sr : hsiwr.getSecurityRatingsAccepted()) {
          index.write("          <div class=\"Cipher\">");
          index.write("<div id=\"Name\">" + sr.getCipherSuite().getTlsVersion() + "__" 
              + sr.getCipherSuite().getCipherSuite().replace('-','_') + "__" 
              + sr.getCipherSuite().getBits() + "bits</div>");
          double rating = new BigDecimal(sr.getValue()).setScale(2, RoundingMode.HALF_UP).doubleValue();
          index.write("<div id=\"Rating\">");
          index.write(rating + "</div>");
          index.newLine();
          
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">Handshake</div>"
              + "<div id=\"Content\">" + sr.getDescriptionHandshake() + "</div></div>");
          index.newLine();
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">Bulk Cipher</div>"
              + "<div id=\"Content\">" + sr.getDescriptionBulkCipher() + "</div></div>");
          index.newLine();
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">Hash</div"
              + "><div id=\"Content\">" + sr.getDescriptionHash() + "</div></div>");
          index.newLine();
          index.write("            <div class=\"CipherSuiteDescription\"><div id=\"Type\">TLS-Version</div>"
              + "<div id=\"Content\">" + sr.getDescriptionTlsVersion() + "</div></div>");
          index.newLine();
          
          index.write("          </div>"); // end Cipher
          index.newLine();
        }
        index.write("        </div>"); // end CipherList
        index.newLine();

        index.write("      </div>"); // end Crawl
        index.newLine();
      }
      
      index.write("    </div>"); // end HostSslInfo
      index.newLine();
      index.write("  </body>");
      index.newLine();
      index.write("</html>");
      
      
      index.close();
      fw.close();
    }
    
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
    index.write("text-align:center; color: white;}");
    index.newLine();
    
    index.write("body { \n  background: steelblue; }");
    index.newLine();
    
    index.write("section {");
    index.newLine();
    index.write("  float: left; }");
    index.newLine();
    index.write("aside {");
    index.newLine();
    index.write("  float: right; }");
    index.newLine();
    //-------------------------------------
    //---------Style of ordered list-------
    index.write(" ol {");
    index.newLine();
    index.write("  border:solid; color: white; display: block; }");
    index.newLine();

    index.write("li { ");
    index.newLine();
    index.write("  margin-left: 30px; }");
    index.newLine();
    
    index.write("ol.other-hosts li > dl {");
    index.newLine();
    index.write("  display: none; }");
    index.newLine();
    index.write("ol.other-hosts li:hover > dl {");
    index.newLine();
    index.write("  display: block; }");
    index.newLine();
    index.write("iframe { position:absolute; right:0px; bottom:10px; width: 60%; "
        + "height: 80%; border: none; }");
    index.newLine();
    //-------------------------------------
    //-------------Style of HostData-------
    index.write("#Title {");
    index.write("  font-weight:bold; }");
    index.newLine();
    
    index.write(".HostSslInfo #Title {");
    index.newLine();
    index.write("  min-height: 40px; color:blue; }");
    index.newLine();
    
    index.write(".Crawl {");
    index.newLine();
    index.write("  color: white;}");
    index.newLine();
    
    index.write(".Crawl #Time {");
    index.newLine();
    index.write("  float:left; width:90%; }");
    index.newLine();

    index.write(".Crawl #Rating {");
    index.newLine();
    index.write("  float:right; width:10%; }");
    index.newLine();

    index.write(".CipherList #Title {");
    index.newLine();
    index.write("  color:green; float:left; width:100%; }");
    index.newLine();

    index.write(".CipherList .Cipher {");
    index.newLine();
    index.write("  display: none; color: white; }");
    index.newLine();
    
    index.write(".CipherSuiteDescription {");
    index.newLine();
    index.write("  display: none; color: black; }");
    index.newLine();
    
    index.write(".CipherList:hover .Cipher {");
    index.newLine();
    index.write("  display: block; }");
    index.newLine();
    
    index.write(".Cipher:hover .CipherSuiteDescription {");
    index.newLine();
    index.write("  display: block; }");
    index.newLine();
    
    index.write(".Cipher .CipherSuiteDescription:hover {");
    index.newLine();
    index.write("  color: blue; }");
    index.newLine();
    
    index.write(".Cipher #Name {");
    index.newLine();
    index.write("  float:left; width:90%; }");
    index.newLine();
    
    index.write(".Cipher #Rating {");
    index.newLine();
    index.write("  float:right; width:10%; }");
    index.newLine();
    //-------------------------------------
    //------Style of CipherSuiteData-------
    index.write(".CipherSuite {");
    index.newLine();
    index.write("float:left; width: 100%; color: white;}");
    index.newLine();
      
    index.write(".CipherSuite .CipherSuiteDescription {");
    index.newLine();
    index.write("display: none; }");
    index.newLine();
      
    index.write(".CipherSuite:hover .CipherSuiteDescription {");
    index.newLine();
    index.write("display: block; }");
    index.newLine();
      
    index.write(".CipherSuite .CipherSuiteDescription:hover {");
    index.newLine();
    index.write("color: blue; }");
    index.newLine();
      
    index.write(".CipherSuiteData #Title{");
    index.newLine();
    index.write("float:left; width:80%; font-weight:bold; min-height: 40px; }");
    index.newLine();

    index.write(".CipherSuiteData #Time{");
    index.newLine();
    index.write("float:right; width:20%; }");
    index.newLine();

    index.write(".CipherSuiteData #Name {");
    index.newLine();
    index.write("float:left; width:90%; }");
    index.newLine();
    
    index.write(".CipherSuiteData #Rating {");
    index.newLine();
    index.write("float:right; width:10%; }");
    index.newLine();
    
    index.write(".CipherSuiteDescription #Type {");
    index.newLine();
    index.write("float:left; width:15%; }");
    index.newLine();
    index.write(".CipherSuiteDescription #Content {");
    index.newLine();
    index.write("float:right; width:85%; }");
    index.newLine();
    //-------------------------------------
    
    index.close();
    fw.close();
  }
  
  /**
   * Get the current Date
   * 
   * @return Date
   */
  private String getCurrentDate(boolean forReport) {
    DateFormat dateFormat;
    if (forReport)
      dateFormat = new SimpleDateFormat("MMM. dd, yyyy");
    else
      dateFormat = new SimpleDateFormat("dd.MM.yyyy");
    
    //get current date time with Date()
    Date date = new Date();
    return dateFormat.format(date);
  }
  
  private String getCrawlTime(long millis) {
    DateFormat dateFormat = new SimpleDateFormat("MMM. dd, yyyy");
    //get current date time with Date()
    Date date = new Date(millis);
    return dateFormat.format(date);
  }
  
  /**
   * Creates the output folder for the analysis
   * 
   * @return none
   */
  private void createOutputFolder() {
    currentFolder = "./" + plainFolder + "." + getCurrentDate(false) + "/";
    
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
    
    // at first insert the last recent crawl per host
    for (Map.Entry<String, HostSslInfo> lastRecentHostInfo : DatabaseManager.getInstance().
                                                             getLastHostSslInfos().entrySet()) {
      ArrayList<HostSslInfoWithRating> list_tmp = new ArrayList<HostSslInfoWithRating>();
      list_tmp.add(new HostSslInfoWithRating(lastRecentHostInfo.getValue()));
      hostSslInfoToAnalyze.put(lastRecentHostInfo.getKey(), list_tmp);
    }
    
    // now add the other crawls as well
    for (HostSslInfo hsi : hsir.findAll())
    {      
      if (hostSslInfoToAnalyze.containsKey(hsi.getHostSslName())) {
        // add to the list of the corresponding host
        long timeDiff = hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).getTimestamp() 
                        - hsi.getTimestamp();
        if (timeDiff == 0)
          continue;
        else if (timeDiff <= hostMergeTime) {
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).addAccepted(hsi.getAccepted());
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).addFailed(hsi.getFailed());
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).addPreferred(hsi.getPreferred());
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).addRejected(hsi.getRejected());
          //out.println("merged host " + hsi.getHostSslName());
        }
        else
          hostSslInfoToAnalyze.get(hsi.getHostSslName()).add(new HostSslInfoWithRating(hsi));
        // only latest crawl and therefore check if current timestamp is bigger than the one in the array
//        else if (hostSslInfoToAnalyze.get(hsi.getHostSslName()).get(0).getTimestamp() < 
//            hsi.getTimestamp()) TODO: delete if no longer needed
      }
      else {// create new ArrayList
        System.err.println("That should not happen! All entries of hosts should already exist!");
        ArrayList<HostSslInfoWithRating> list_tmp = new ArrayList<HostSslInfoWithRating>();
        list_tmp.add(new HostSslInfoWithRating(hsi));
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
    Set<String> acceptedEmpty  = new HashSet<String>();
    Set<String> preferredEmpty = new HashSet<String>();
    SslRating tmpRating;
    try {
      //iterate over all hosts in the map
      for (Map.Entry<String, ArrayList<HostSslInfoWithRating>> entry : hostSslInfoToAnalyze.entrySet()) {
        // iterate over all HostSslInfoWithRating in the ArrayList of every host in the map
        for (HostSslInfoWithRating hsiwr : entry.getValue()) {
          // get the Cipher-Rating for accepted and store it in HostSslInfoWithRating
          for (CipherSuite cs : hsiwr.getAccepted()) {
            tmpRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
            hsiwr.addSslRatingToSecurityRatingsAccepted(tmpRating);
            String csName = cs.getTlsVersion() + "__" + cs.getCipherSuite().replace("-", "_") + "__"
                            + cs.getBits() + "bits";
            cipherSuitesPlain.put(csName , tmpRating);
          }
          // get the Cipher-Rating for preferred and store it in HostSslInfoWithRating
          for (CipherSuite cs : hsiwr.getPreferred()) {
            tmpRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
            hsiwr.addSslRatingToSecurityRatingsPreferred(tmpRating);
            String csName = cs.getTlsVersion() + "__" + cs.getCipherSuite().replace("-", "_") + "__"
                + cs.getBits() + "bits";
             cipherSuitesPlain.put(csName , tmpRating);
          }
          // now calcualte the overall rating for every HostSslInfoWithRating per host
          calculationCount++;
          hsiwr.calculateOverallRating(acceptedEmpty, preferredEmpty);
          hsiwr.sortSecurityRatingsSets();
//          if (calculationCount % 600 == 0) {
//            out.println("###################Some testing output.#######################");
//            printSslRatingSet(hsiwr.getSecurityRatingsAccepted(), "AcceptedCiphers");
//            printSslRatingSet(hsiwr.getSecurityRatingsPreferred(), "PreferredCiphers");
//            out.println("##########The overall Rating for the host " + hsiwr.getHostSslName() + 
//                " is: " + hsiwr.getOverallRating()); TODO: remove if no longer needed
//          }
        }
        // sort the overall rating per host
        Collections.sort(entry.getValue(), new ComparatorHostSslInfoWithRating());
      }
      
      //printWarningEmpty("accepted", acceptedEmpty);
      //printWarningEmpty("preferred", preferredEmpty);
      
      // sort the hosts in the map
      ComparatorMapStringHostSslInfoWithRating ratingValueComparator = 
          new ComparatorMapStringHostSslInfoWithRating(hostSslInfoToAnalyze);
      hostSslInfoSorted = new TreeMap<String, ArrayList<HostSslInfoWithRating>>(ratingValueComparator);
      hostSslInfoSorted.putAll(hostSslInfoToAnalyze);
      hostSslInfoToAnalyze.clear();
      
      // sort the ciphers in the map for ciphersuites
      ComparatorMapStringSslRating sslRatingComparator = 
          new ComparatorMapStringSslRating(cipherSuitesPlain);
      cipherSuitesSorted = new TreeMap<String, SslRating>(sslRatingComparator);
      cipherSuitesSorted.putAll(cipherSuitesPlain);
      cipherSuitesPlain.clear();
      
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
          + "CipherSuite is " + r.getCipherSuite().getCipherSuite() + " and Description is: " + r.getDescriptionDefault());
    }
  }
  
  private void printWarningEmpty(String type, Set<String> emptyList) {
    out.println("WARNING: List of " + type + " Cipher-Suites is empty for the following hosts: \n"); 
    
    int i = 1;
    for (String host : emptyList) {
      if (i % 10 == 0) {
        out.println(host.trim() + ", ");
        i = 0;
      }
      else {
        out.print(host.trim() + ", ");
      }
      i++;
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
    firstRun = false;
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

  public int setHostMergeTime() {
    long time = -1;
    BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
    
    while (time < 0)
    {
      try {
        out.println("Amount of hours to merge older crawls of a host with the newest one (in hours): ");
        time = Long.parseLong(console.readLine());
      } 
      catch (Exception e) {
        System.err.println(e.getMessage());
        e.printStackTrace();
        time = -1;
      }
      
      if (time < 0) {
        out.println("Please choose a positive number of hours");
      }
      
    }
    
    hostMergeTime = time*60*60*1000; // time stored in milliseconds
    return 0;
  }
}
