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
public class AnalysisCertificateValid extends Analysis
{
  private CertificateFactory                                      cf;
  private KeyStore                                                ks;
  private PKIXParameters                                          params;
  private KeyStore                                                keystore;
  private CertPathValidator                                       cpv;
  private BrowserCompatHostnameVerifier                           hostNameVerifier;

  protected List<Map.Entry<HostInfo, SSLException>>               invalidHostnames;
  protected List<Map.Entry<HostInfo, CertPathValidatorException>> certPathValidatorExceptions;
  protected List<Map.Entry<HostInfo, X509Certificate>>            expiredCertificates;
  protected List<Map.Entry<HostInfo, X509Certificate>>            notYetValidCertificates;
  protected List<HostInfo>                                        validCerts;
  protected List<HostInfo>                                        noTrustAnchor;

  // Certificates grouped by different values
  protected Map<String, Map<String, Set<X509Certificate>>>        cgv;

  protected long                                                  maxCertSize;
  protected long                                                  sumCertSize;
  protected long                                                  countCertSize;
  protected long                                                  avgCertSize;
  protected HostInfo                                              maxCertSizeHostInfo;

  protected Map<BigInteger, Set<X500Principal>>                   moduli;
  protected Map<BigInteger, Set<X500Principal>>                   exponents;

  protected long                                                  tree_id = 0;

  /**
   * Root Certificate --> Child Certificates
   */
  protected Map<X500Principal, CertificateTree>                   inverseCertificateTree;

  public class CertificateTree
  {
    X509Certificate                     cert    = null;
    Map<X500Principal, CertificateTree> childs  = new HashMap<X500Principal, CertificateTree>();
    CertificateTree                     parent  = null;
    HostInfo                            example = null;
  }

  public AnalysisCertificateValid()
  {
    super();
  }

  public AnalysisCertificateValid(boolean showDetails)
  {
    super(showDetails);
  }

  public AnalysisCertificateValid(long useCrawlingSessionID,
      boolean showDetails)
  {
    super(useCrawlingSessionID, showDetails);
  }

  @Override
  public void init()
  {
    this.name = "Cert Valid?";
    this.description = "Which Certificates not valid and why?";
    try
    {
      cf = CertificateFactory.getInstance("X.509");
      cpv = CertPathValidator.getInstance("PKIX");

      String filename = System.getProperty("java.home")
          + "/lib/security/cacerts".replace('/', File.separatorChar);
      FileInputStream is = new FileInputStream(filename);

      keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      String password = "changeit";
      keystore.load(is, password.toCharArray());
      params = new PKIXParameters(keystore);
      params.setRevocationEnabled(false);
      // TODO: enable revocation lists:
      // http://stackoverflow.com/questions/12456079/java-keystore-verify-signed-certificate

      // same as Curl and Firefox
      hostNameVerifier = new BrowserCompatHostnameVerifier();

    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }

  // certificate chain check inspired by:
  // http://www.java2s.com/Tutorial/Java/0490__Security/Validatecertificate.htm
  // http://stackoverflow.com/questions/3508050/how-can-i-get-a-list-of-trusted-root-certificates-in-java

  protected void checkCertificate(List<X509Certificate> chain, HostInfo hi)
  {
    boolean valid = true;
    // check valid chain
    try
    {
      CertPath cp = cf.generateCertPath(chain);
      PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
    }
    catch (CertificateException e2)
    {
      // subclasses: CertificateEncodingException,
      // CertificateExpiredException,
      // CertificateNotYetValidException,
      // CertificateParsingException
      e2.printStackTrace();
      valid = false;
    }
    catch (CertPathValidatorException e2)
    {
      // out.println("CertPathValidatorException at: "+hi.getHostName());
      out.println("Bad HTTPS 4: CertPathValidatorException: " + e2.getMessage() + " -> "
          + e2.getReason());
      if (e2.getReason().toString().equals("NO_TRUST_ANCHOR"))
      {
        noTrustAnchor.add(hi);
      }
      else
      {
        certPathValidatorExceptions
            .add(new AbstractMap.SimpleEntry<HostInfo, CertPathValidatorException>(hi, e2));
      }
      valid = false;
    }
    catch (InvalidAlgorithmParameterException e2)
    {
      e2.printStackTrace();
      valid = false;
    }

    // verify hostname
    try
    {
      hostNameVerifier.verify(hi.getHostName(), chain.get(0));
    }
    catch (SSLException e)
    {
      invalidHostnames.add(new AbstractMap.SimpleEntry<HostInfo, SSLException>(hi, e));
      out.println("Bad HTTPS 3: SSLException: " + e.getMessage());
      valid = false;
    }
    catch (Exception e)
    {
      // TODO: Other exceptions (e.g. NullPointer!)
      invalidHostnames.add(new AbstractMap.SimpleEntry<HostInfo, SSLException>(hi, null));
      out.println("Bad HTTPS 3: SSLException: " + e.getMessage());
      valid = false;
    }

    // check time
    try
    {
      // TODO: check other cert elements
      chain.get(0).checkValidity(new Date()); // TODO:
      // original date
    }
    catch (CertificateExpiredException e)
    { // TODO
      out.println("Bad HTTPS 2: CertificateExpiredException: " + e.getMessage());
      expiredCertificates.add(new AbstractMap.SimpleEntry<HostInfo, X509Certificate>(hi, chain
          .get(0)));
      valid = false;
    }
    catch (CertificateNotYetValidException e)
    { // TODO
      out.println("Bad HTTPS 1: CertificateNotYetValidException: " + e.getMessage());
      notYetValidCertificates.add(new AbstractMap.SimpleEntry<HostInfo, X509Certificate>(hi, chain
          .get(0)));
      valid = false;
    }

    if (valid)
    {
      validCerts.add(hi);
    }
  }

  protected void addKeyValueStatistic(X509Certificate cert, String key,
      String value)
  {
    if (!cgv.containsKey(key))
    {
      cgv.put(key, new HashMap<String, Set<X509Certificate>>());
    }
    Map<String, Set<X509Certificate>> values = cgv.get(key);
    if (!values.containsKey(value))
    {
      values.put(value, new HashSet<X509Certificate>());
    }
    values.get(value).add(cert);
  }

  protected void insertCertificateInInverseTree(X509Certificate cert)
  {
    if (!inverseCertificateTree.containsKey(cert.getIssuerX500Principal()))
    {
      inverseCertificateTree.put(cert.getIssuerX500Principal(), new CertificateTree());
    }
    if (!inverseCertificateTree.containsKey(cert.getSubjectX500Principal()))
    {
      inverseCertificateTree.put(cert.getSubjectX500Principal(), new CertificateTree());
    }
    CertificateTree issuer = inverseCertificateTree.get(cert.getIssuerX500Principal());
    CertificateTree subject = inverseCertificateTree.get(cert.getSubjectX500Principal());
    subject.parent = issuer;
    issuer.childs.put(cert.getSubjectX500Principal(), subject);
    subject.cert = cert;
  }

  protected void groupCertificates(List<X509Certificate> chain, HostInfo hi)
  {
    for (X509Certificate cert : chain)
    {
      addKeyValueStatistic(cert, "SigAlgName", cert.getSigAlgName());
      addKeyValueStatistic(cert, "SigAlgOID", cert.getSigAlgOID());

      PublicKey pk = cert.getPublicKey();
      addKeyValueStatistic(cert, "PK-Algorithm", pk.getAlgorithm());
      // DHPublicKey, DSAPublicKey, ECPublicKey, RSAPublicKey
      if (pk instanceof DHPublicKey)
      {
        DHPublicKey dh_pk = (DHPublicKey) pk;
      }
      if (pk instanceof DSAPublicKey)
      {
        DSAPublicKey dsa_pk = (DSAPublicKey) pk;
      }
      if (pk instanceof ECPublicKey)
      {
        ECPublicKey ec_pk = (ECPublicKey) pk;
      }
      if (pk instanceof RSAPublicKey)
      {
        RSAPublicKey rsa_pk = (RSAPublicKey) pk;
        int bitSize = rsa_pk.getModulus().bitLength();
        addKeyValueStatistic(cert, "RSA-Modulus-Bitlength", String.valueOf(bitSize));
        rsa_pk.getPublicExponent();

        // Check for same Modulus
        BigInteger N = rsa_pk.getModulus();
        if (!moduli.containsKey(N))
        {
          moduli.put(N, new HashSet<X500Principal>());
        }
        moduli.get(N).add(cert.getSubjectX500Principal());

        // Check for same Exponent
        BigInteger e = rsa_pk.getPublicExponent();
        if (!exponents.containsKey(e))
        {
          exponents.put(e, new HashSet<X500Principal>());
        }
        exponents.get(e).add(cert.getSubjectX500Principal());
      }
      addKeyValueStatistic(cert, "BasicConstraints",
          String.valueOf(cert.getBasicConstraints()));
      addKeyValueStatistic(cert, "Type", String.valueOf(cert.getType()));

      if (cert.getCriticalExtensionOIDs() != null)
        for (String v : cert.getCriticalExtensionOIDs())
        {
          addKeyValueStatistic(cert, "CriticalExtensionOID", v);
        }
      if (cert.getNonCriticalExtensionOIDs() != null)
        for (String v : cert.getNonCriticalExtensionOIDs())
        {
          addKeyValueStatistic(cert, "NonCriticalExtensionOID", v);
        }
      boolean[] keyUsage = cert.getKeyUsage();
      if (keyUsage != null)
        for (int i = 0; i < keyUsage.length; i++)
        {
          if (keyUsage[i])
          {
            addKeyValueStatistic(cert, "KeyUsage",
                String.valueOf(i) + " = " + resolveKeyUsage(i));
          }
        }

      try
      {
        if (cert.getExtendedKeyUsage() != null)
          for (String v : cert.getExtendedKeyUsage())
          {
            addKeyValueStatistic(cert, "ExtendedKeyUsage(OID)", v);
          }
      }
      catch (CertificateParsingException e)
      {
      }
    }

  }

  public String resolveKeyUsage(int i)
  {
    switch (i)
    {
    case 0:
      return "digitalSignature";
    case 1:
      return "nonRepudiation";
    case 2:
      return "keyEncipherment";
    case 3:
      return "dataEncipherment";
    case 4:
      return "keyAgreement";
    case 5:
      return "keyCertSign";
    case 6:
      return "cRLSign";
    case 7:
      return "encipherOnly";
    case 8:
      return "decipherOnly";
    default:
      return "?";
    }
  }

  OIDResolver oidResolver;

  protected void resetAnalysis()
  {
    invalidHostnames = new ArrayList<Map.Entry<HostInfo, SSLException>>();
    expiredCertificates = new ArrayList<Map.Entry<HostInfo, X509Certificate>>();
    notYetValidCertificates = new ArrayList<Map.Entry<HostInfo, X509Certificate>>();
    certPathValidatorExceptions = new ArrayList<Map.Entry<HostInfo, CertPathValidatorException>>();
    noTrustAnchor = new ArrayList<HostInfo>();
    validCerts = new ArrayList<HostInfo>();
    cgv = new HashMap<String, Map<String, Set<X509Certificate>>>();
    inverseCertificateTree = new HashMap<X500Principal, CertificateTree>();
    this.maxCertSize = 0;
    this.sumCertSize = 0;
    this.countCertSize = 0;
    this.avgCertSize = 0;
    this.maxCertSizeHostInfo = null;

    moduli = new HashMap<BigInteger, Set<X500Principal>>();
    exponents = new HashMap<BigInteger, Set<X500Principal>>();
    oidResolver = new OIDResolver();
    oidResolver.loadTxtFile("evcerts.txt");
  }

  private void buildInverseCertificateChain(List<X509Certificate> chain, HostInfo hostInfo)
  {
    CertificateTree current = null;
    for (int i = chain.size() - 1; i >= 0; i--)
    {
      X509Certificate cert = chain.get(i);
      X500Principal subject = cert.getSubjectX500Principal();
      X500Principal issuer = cert.getIssuerX500Principal();
      if (current == null) // root certificate
      {
        if (!inverseCertificateTree.containsKey(subject))
        {
          current = new CertificateTree();
          inverseCertificateTree.put(subject, current);
          current.parent = current;
          current.cert = cert;
          current.example = hostInfo;
        }
        else
        {
          current = inverseCertificateTree.get(subject);
        }
      }
      else
      {
        if (current.childs.containsKey(subject))
        {
          current = current.childs.get(subject);
        }
        else
        {
          CertificateTree _new = new CertificateTree();
          _new.cert = cert;
          _new.parent = current;
          _new.example = hostInfo;
          current.childs.put(subject, _new);
          current = _new;
        }
      }
    }
  }

  @Override
  public int analyze()
  {
    this.resetAnalysis();

    for (HostInfo hi : this.getHostsToAnalyze())
    {
      // Make Statistic about Certificate sizes
      Long certSize = hi.getCertificateSize();
      if (certSize != null && certSize > 0)
      {
        this.sumCertSize += certSize;
        this.countCertSize++;
        if (certSize > this.maxCertSize)
        {
          this.maxCertSize = certSize;
          maxCertSizeHostInfo = hi;
        }
      }

      // Load and Sort Certificate Chain
      Set<Certificate> certs = hi.getCert();
      if (certs.size() > 0)
      {
        List<X509Certificate> chain = CertificateSorter.parseCertificates(certs);
        groupCertificates(chain, hi);
        chain = CertificateSorter.sortCertificates(chain);
        // Check if Certificate is valid:
        checkCertificate(chain, hi);

        // Version 1: does not work if cert has a loop in the issuers, e.g. the following
        // SQL-Command returns 3 different issuers (what should not be this way, but it is):
        // select distinct issuer from Certificate where subject =
        // "CN=AddTrust External CA Root, OU=AddTrust External TTP Network, O=AddTrust AB, C=SE";
        // for (X509Certificate cert : chain)
        // {
        // insertCertificateInInverseTree(cert);
        // }

        // Version 2: start with root certificate, only store root certs in list.
        buildInverseCertificateChain(chain, hi);

      }
    }
    if (this.countCertSize > 0)
    {
      this.avgCertSize = this.sumCertSize / this.countCertSize;
    }
    return 0;
  }

  private String escape(String text)
  {
    text = text.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;")
        .replace(">", "&gt;").replace(" ", "&nbsp;");
    return text;
  }

  void recursive_exportInvsereTree(CertificateTree node, int depth,
      BufferedWriter index, BufferedWriter detail, String detailPath)
      throws IOException
  {
    String url = "#";
    if (node.example != null)
    {
      url = "https://" + node.example.getHostName();
    }
    if (node.cert == null)
    {
      if (node.childs.size() > 0)
      {
        CertificateTree child = node.childs.values().iterator().next();
        if (child.cert != null)
        {
          String sub = child.cert.getIssuerX500Principal().toString();
          sub = escape(sub);
          detail.write("<li id=\"" + tree_id + "\">Certificate Chain missing: <strike>"
              + "<a href=\"" + url + "\">" + sub
              + "</a></strike>");
          if (depth == 0)
          {
            index.write("<li>Certificate Chain missing: <strike><a href=\"" + detailPath + "#"
                + tree_id + "\">" + sub + "</a></strike></li>");
            index.newLine();
          }
        }
      }
    }
    else
    {
      String sub = node.cert.getSubjectX500Principal().toString();
      sub = escape(sub);
      detail.write("<li id=\"" + tree_id + "\">" + "<a href=\"" + url + "\">" + sub + "</a>");
      if (depth == 0)
      {
        index.write("<li><a href=\"" + detailPath + "#" + tree_id + "\">" + sub + "</a></li>");
        index.newLine();
      }
    }
    tree_id++;

    if (node.childs.size() > 0)
    {
      detail.write("<ul>");
      detail.newLine();
      for (CertificateTree child : node.childs.values())
      {
        // self signed certificate causes endless recursion
        if (child != node)
        {
          // TODO: set a meaningfull value or remove if
          if (depth < 20) // aborting after max 20 steps (e.g.)
          {
            recursive_exportInvsereTree(child, depth + 1, index,
                detail, detailPath);
          }
          else
          {
            detail.write("<li>Aborted Tree after 20 recursions (endless?)</li>");
          }
        }
      }
      detail.write("</ul>");
    }

    detail.write("</li>");
    detail.newLine();
  }

  void exportInverseTree(BufferedWriter index, String folder)
      throws IOException
  {

    File indexFile = new File(folder, "cert_inverse.html");
    FileWriter fw = new FileWriter(indexFile, false);
    BufferedWriter detail = new BufferedWriter(fw);

    index.write("<ul>");
    index.newLine();
    for (X500Principal key : inverseCertificateTree.keySet())
    {
      CertificateTree node = inverseCertificateTree.get(key);
      // is root certificate
      if (node.parent == null || node.parent == node)
      {
        recursive_exportInvsereTree(node, 0, index, detail,
            this.getRelativePath(indexFile, new File(folder)));
      }
    }
    index.write("</ul>");
    index.newLine();
  }

  void exportGroupedDetails(BufferedWriter index, String folder)
      throws IOException
  {

    for (Map.Entry<String, Map<String, Set<X509Certificate>>> cg : cgv
        .entrySet())
    {
      index.write("<h2>" + cg.getKey() + " (" + cg.getValue().size()
          + ")</h2><ul>");

      File indexFile = new File(folder, "certgroup_" + cg.getKey() + ".html");
      FileWriter fw = new FileWriter(indexFile, false);
      BufferedWriter detail = new BufferedWriter(fw);

      detail.write("<h1>Certificate Details: " + cg.getKey() + "</h1>");
      for (Map.Entry<String, Set<X509Certificate>> c : cg.getValue()
          .entrySet())
      {
        String a = "";
        String b = "";
        if (cg.getKey().toLowerCase().contains("oid"))
        {
          String value = oidResolver.resolve(c.getKey());
          if (value != null)
          {
            a = "<font color=\"red\">";
            b = " - " + value + "</font>";
          }
          else
          {
            b = " <a href=\"http://oid-info.com/get/" + c.getKey() + "\">[resolve]</a> ";
          }
        }
        index.write("<li>" + a + "<a href=\"" + this.getRelativePath(indexFile, new File(folder))
            + "#" + c.getKey()
            + "\">" + c.getKey() + "</a>" + b + " (" + c.getValue().size() + ")</li>");
        index.newLine();
        detail.write("<h2 id=\"" + c.getKey() + "\">" + a + c.getKey() + b + " ("
            + c.getValue().size() + ")</h2><ul>");
        for (X509Certificate certs : c.getValue())
        {
          detail.write("<li>"
              + certs.getSubjectX500Principal().toString()
              + "</li>");
        }
        detail.write("</ul>");
      }
      index.write("</ul>");
      detail.close();
      fw.close();
    }
  }

  void exportValidDetails(BufferedWriter index) throws IOException
  {
    index.write("<h2 id=\"validity\">&Uuml;bersicht</h2><ul>");
    index.write("  <li><a href=\"#valid\">Valid Certificates</a>: " + validCerts.size() + "</li>");
    index.write("  <li><a href=\"#invalid_hostname\">Invalid Hostnames</a>: "
        + invalidHostnames.size() + "</li>");
    index.write("  <li><a href=\"#expired\">Expired Certificates</a>: "
        + expiredCertificates.size() + "</li>");
    index.write("  <li><a href=\"#not_yet_valid\">Not yet valid</a>: "
        + notYetValidCertificates.size() + "</li>");
    index.write("  <li><a href=\"#no_trust_anchor\">No Trust Anchor</a>: " + noTrustAnchor.size()
        + "</li>");
    index.write("  <li><a href=\"#exception\">CertPath Validator Exceptions</a>: "
        + certPathValidatorExceptions.size() + "</li>");
    index.write("</ul>");
    index.newLine();

    // Valid Certificates
    index.write("<h2 id=\"valid\">Valid Certificates</h2><ul>");
    for (HostInfo hi : validCerts)
    {

      String server = hi.getHostName();
      index.write("  <li><a href=\"https://" + server + "\">" + server
          + "</a></li>");
      index.newLine();
    }
    index.write("</ul>");
    index.newLine();

    // Invalid Hostnames
    index.write("<h2 id=\"invalid_hostname\">Invalid Hostnames</h2><ul>");
    for (Map.Entry<HostInfo, SSLException> pair : invalidHostnames)
    {
      String server = pair.getKey().getHostName();
      String message = "(null)";
      if (pair.getValue() != null)
      {
        message = pair.getValue().getMessage().replace("<", "&lt;").replace(">", "&gt;");
      }
      index.write("  <li><a href=\"https://" + server + "\">" + server + "</a>: " + message
          + "</li>");
      index.newLine();
    }
    index.write("</ul>");
    index.newLine();

    // Expired
    index.write("<h2 id=\"expired\">Expired Certificates</h2><ul>");
    for (Map.Entry<HostInfo, X509Certificate> pair : expiredCertificates)
    {
      String server = pair.getKey().getHostName();
      String message = pair.getValue().getNotAfter().toLocaleString();
      index.write("  <li><a href=\"https://" + server + "\">" + server
          + "</a>: " + message + "</li>");
      index.newLine();
    }
    index.write("</ul>");
    index.newLine();

    // Not Yet Valid
    index.write("<h2 id=\"not_yet_valid\">Not Yet Valid Certificates</h2><ul>");
    for (Map.Entry<HostInfo, X509Certificate> pair : notYetValidCertificates)
    {
      String server = pair.getKey().getHostName();
      String message = pair.getValue().getNotBefore().toLocaleString();
      index.write("  <li><a href=\"https://" + server + "\">" + server
          + "</a>: " + message + "</li>");
      index.newLine();
    }
    index.write("</ul>");
    index.newLine();

    // TrustAnchor
    index.write("<h2 id=\"no_trust_anchor\">4: No Trust Anchors</h2><ul>");
    for (HostInfo hi : noTrustAnchor)
    {
      String server = hi.getHostName();
      index.write("  <li><a href=\"https://" + server + "\">" + server + "</a></li>");
      index.newLine();
    }
    index.write("</ul>");
    index.newLine();

    // Not Yet Valid
    index.write("<h2 id=\"exception\">4: CertPathValidatorException</h2><ul>");
    for (Map.Entry<HostInfo, CertPathValidatorException> pair : certPathValidatorExceptions)
    {
      String server = pair.getKey().getHostName();
      String message = pair.getValue().getReason().toString() + ": "
          + pair.getValue().getMessage();
      index.write("  <li><a href=\"https://" + server + "\">" + server + "</a>: " + message
          + "</li>");
      index.newLine();
    }
    index.write("</ul>");
    index.newLine();
  }

  @Override
  public String exportToFolder(String folder)
  {
    try
    {
      File indexFile = new File(folder, "certvalid.html");
      FileWriter fw = new FileWriter(indexFile, false);
      BufferedWriter index = new BufferedWriter(fw);
      // Index
      index.write("<html><body><h1>Certificates</h1>");
      index.write("<ul>");
      index.write("<li><a href=\"#cert_sizes\">Certificate Sizes</a></li>");
      index.write("<li><a href=\"#validity\">Validity</a></li>");

      index.write("<li><a href=\"#cert_grouped\">Certificates Grouped</a></li>");

      index.write("<li><a href=\"#inverse_tree\">Inverse Tree</a></li>");
      index.write("<li><a href=\"#same_moduli\">Same Moduli</a></li>");
      index.write("<li><a href=\"#same_exponent\">Same Exponents</a></li>");
      index.write("</ul>");
      index.newLine();

      // Certificate Sizes
      index.write("<h2 id=\"cert_sizes\">Certificate Sizes</h2>");
      index.write("<p>Max Certificate Size is <b>" + this.maxCertSize
          + "</b> and average certificate size is <b>" + this.avgCertSize + "</b>.</p>");
      String maxName = this.maxCertSizeHostInfo.getHostName();
      index.write("<p>Host with largest Certificate: <a href=\"https://" + maxName + "\">"
          + maxName + "</a></p>");

      this.exportValidDetails(index);

      index.write("<h1 id=\"cert_grouped\">Certificates Grouped</h1>");
      this.exportGroupedDetails(index, folder);

      index.write("<h1 id=\"inverse_tree\">Inverse Tree</h1>");
      this.exportInverseTree(index, folder);

      index.write("<h1 id=\"same_moduli\">Same Moduli</h1><ul>");
      index.newLine();
      for (BigInteger modulus : moduli.keySet())
      {
        Set<X500Principal> principals = moduli.get(modulus);
        if (principals.size() > 1)
        {
          index.write("<li>Modulus: <b>" + modulus + "</b><ul>");
          index.newLine();
          for (X500Principal principal : principals)
          {
            index.write("  <li>" + principal + "</li>");
            index.newLine();
          }
          index.write("</ul></li>");
        }
      }
      index.write("</ul>");

      index.write("<h1 id=\"same_exponent\">Same Exponents</h1>");
      index.newLine();
      for (BigInteger exponent : exponents.keySet())
      {
        Set<X500Principal> principals = exponents.get(exponent);
        if (principals.size() > 1)
        {
          index.write("<li>Exponent: <b>" + exponent + "</b><ul>");
          index.newLine();
          for (X500Principal principal : principals)
          {
            index.write("  <li>" + principal + "</li>");
            index.newLine();
          }
          index.write("</ul></li>");
        }
      }
      index.write("</ul>");

      index.write("</body></html>");
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
