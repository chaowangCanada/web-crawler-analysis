package at.chille.crawler.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.interfaces.DHPublicKey;
import javax.net.ssl.SSLException;
import javax.security.auth.x500.X500Principal;

import org.apache.http.conn.ssl.BrowserCompatHostnameVerifier;

import at.chille.crawler.database.model.Certificate;
import at.chille.crawler.database.model.HostInfo;

/**
 * Verificateon Algorithm
 * 
 * @author chille
 * 
 */
public class AnalysisRunAll extends Analysis
{
  public AnalysisRunAll()
  {
    super();
    this.name = "Execute all Analysis and Export";
  }

  public AnalysisRunAll(boolean showDetails)
  {
    super(showDetails);
    this.name = "Execute all Analysis and Export";
  }

  public AnalysisRunAll(long useCrawlingSessionID,
      boolean showDetails)
  {
    super(useCrawlingSessionID, showDetails);
    this.name = "Execute all Analysis and Export";
  }
  
 

  @Override
  public int analyze()
  {
    out.println("Creating Analysis Classes...");
    String folder = "./export/";
    AnalysisCertificateValid a1 = new AnalysisCertificateValid(false);
    AnalysisCookies a2 = new AnalysisCookies(false);
    AnalysisHeader a3 = new AnalysisHeader(false);
    AnalysisSSL a4 = new AnalysisSSL(false);

    out.println("Loading HostInfos to analyze...");
    Collection<HostInfo> hosts = this.getHostsToAnalyze();
    a1.setHostsToAnalyze(hosts);
    a2.setHostsToAnalyze(hosts);
    a3.setHostsToAnalyze(hosts);
    a4.setHostsToAnalyze(hosts);

    out.println("Analyzing...");
    a1.analyze();
    a2.analyze();
    a3.analyze();
    a4.analyze();

    out.println("Exporting to files...");
    a1.exportToFolder(folder);
    a2.exportToFolder(folder);
    a3.exportToFolder(folder);
    a4.exportToFolder(folder);
    out.println("Finished...");

    return -1; // Exit
  }

}
