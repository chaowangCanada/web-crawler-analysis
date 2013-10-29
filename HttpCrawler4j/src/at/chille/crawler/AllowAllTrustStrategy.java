package at.chille.crawler;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.http.conn.ssl.TrustStrategy;

public class AllowAllTrustStrategy implements TrustStrategy {

	public boolean isTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		// This method is not needed any more to extract the Certificate Chain.
		// But it is needed to bypass the Certificate Check.
		// Invalid Certificates are accepted, so we can store them.


		// CertificateLogger.getInstance().addCertificateChain("", chain);
		// System.out.println("================> "+authType);
		// http://docs.oracle.com/javase/1.5.0/docs/api/java/security/cert/X509Certificate.html?is-external=true
		// for(X509Certificate certelement : chain)
		// {
		// System.out.println("---------------------------------------------CE begin");
		// System.out.println(certelement);
		// System.out.println(certelement.getSigAlgName()+ ", " +
		// certelement.getType()+ ", ");
		// System.out.println("---------------------------------------------CE end");
		// }
		// System.out.println("--------");
		
		return true; // also allow if certificate is not trusted.
		// else the connection will be aborted and we get no HTTP-Headers and no Certificate for this Website
		
		// if we return false, the certificate gets also checked by the default
		// environment
		// throw CertificateException if not trusted or invalid
	}

}
