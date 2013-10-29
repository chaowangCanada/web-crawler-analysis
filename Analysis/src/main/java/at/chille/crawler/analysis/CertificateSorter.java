package at.chille.crawler.analysis;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import at.chille.crawler.database.model.Certificate;

/**
 * Parsing and Sorting Certificates using the Subject and Issuer Principals.
 * @author chille
 *
 */
public class CertificateSorter
{
  private static CertificateFactory cf;

  /**
   * Restores an encoded X509Certificate and stores it at the given position in the chain.
   * @param certs
   * @return
   */
  public static List<X509Certificate> parseCertificates(Set<Certificate> certs)
  {

    if (cf == null)
    {
      try
      {
        cf = CertificateFactory.getInstance("X.509");
      }
      catch (CertificateException e)
      {
        e.printStackTrace();
      }
    }

    // System.out.println("Size: " + certs.size());
    ArrayList<X509Certificate> chain = new ArrayList<X509Certificate>();
    for (int i = 0; i < certs.size(); i++)
    {
      chain.add(null);
    }
    try
    {
      for (Certificate cert : certs)
      {
        byte[] encodedCert = cert.getEncodedCertificate();

        ByteArrayInputStream bais = new ByteArrayInputStream(
            encodedCert);
        X509Certificate certb;
        certb = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        // System.out.println("depth: " + cert.getDepth() +
        // " i"+cert.getIssuer());
        chain.set(cert.getDepth(), certb);
        // out.println(" X509 back again " + certb.getSigAlgName());
      }
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }

    while (chain.size() - 1 > 0 && chain.get(chain.size() - 1) == null)
    {
      chain.remove(chain.size() - 1);
      System.err.println("Duplicate Certificate Stored in database.");
    }

    return chain;
  }

  /**
   * Sorts the Certificate Chain by IssuerDN and SubjectDN. The [0]-Element should be the Hostname,
   * the last Element should be the Root Certificate.
   * 
   * @param certs
   *          The first element must be the correct one.
   * @return sorted Certificate Chain
   */
  public static List<X509Certificate> sortCertificates(
      List<X509Certificate> certs)
  {
    int length = certs.size();
    if (certs.size() <= 1)
    {
      return certs;
    }

    for (X509Certificate cert : certs)
    {
      if (cert == null)
      {
        throw new NullPointerException();
      }
    }

    for (int i = 0; i < length; i++)
    {
      boolean found = false;
      // Principal issuer = certs.get(i).getIssuerDN();
      X500Principal issuer = certs.get(i).getIssuerX500Principal();
      for (int j = i + 1; j < length; j++)
      {
        // Principal subject = certs.get(j).getSubjectDN();
        X500Principal subject = certs.get(j).getSubjectX500Principal();
        if (issuer.equals(subject))
        {
          // sorting necessary?
          if (i + 1 != j)
          {
            X509Certificate tmp = certs.get(i + 1);
            certs.set(i + 1, certs.get(j));
            certs.set(j, tmp);
          }
          found = true;
        }
      }
      if (!found)
      {
        break;
      }
    }

    return certs;
  }
}
