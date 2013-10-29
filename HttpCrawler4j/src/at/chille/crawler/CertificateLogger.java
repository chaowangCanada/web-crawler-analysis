package at.chille.crawler;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import at.chille.crawler.database.model.Certificate;
import at.chille.crawler.database.model.HostInfo;

public class CertificateLogger {
	private static CertificateLogger cl = new CertificateLogger();

	protected CertificateLogger() {

	}

	public static CertificateLogger getInstance() {
		return cl;
	}

	// private HashMap<String, X509Certificate[]> certificates = new
	// HashMap<String, X509Certificate[]>();
	public Set<Certificate> convertCertificate(
			X509Certificate[] certificateChain) {
		Set<Certificate> extractedCerts = new HashSet<Certificate>();

		short i = 0;
		for (X509Certificate cert : certificateChain) {
			// TODO: possible problem here with order of certificate chain?
			Certificate extractedCert = new Certificate();
			extractedCert.setIssuer(cert.getIssuerDN().toString());
			extractedCert.setSignatureAlgorithm(cert.getSigAlgName());
			extractedCert.setSubject(cert.getSubjectDN().toString());
			extractedCert.setType(cert.getType());
			extractedCert.setDepth(Short.valueOf(i));

			// save additional information
			extractedCert.setBasicConstraints(cert.getBasicConstraints());
			extractedCert.setKeyUsage(Arrays.toString(cert.getKeyUsage()));
			try {
				List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
				if(extendedKeyUsage != null)
				{
					extractedCert.setExtendedKeyUsage(extendedKeyUsage.toString());
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			extractedCert.setPkAlgorithm(cert.getPublicKey().getAlgorithm());
			extractedCert.setPublicKey(cert.getPublicKey().getEncoded());

			// Testing more information extraction:
			/*
			 * System.out.println("KeyUsage: "+
			 * Arrays.toString(cert.getKeyUsage())); // KeyUsage: [false, false,
			 * false, false, false, true, true, false, false]
			 * System.out.println("PK-Alg: "+
			 * cert.getPublicKey().getAlgorithm()); // PK-Alg: RSA
			 * System.out.println("Basic Constraints: "+
			 * cert.getBasicConstraints()); // Basic Constraints: 0
			 * System.out.println("PK: "+ cert.getPublicKey()); // PK: Sun RSA
			 * public key, 2048 bits // modulus:
			 * 23223460521213001555387570833114089730860753895612098652836669980305042236333373520864248457295413309113206184129614795458813002793321404739348347239478157361314575018921060208560207337879261682185633570259454980009323505955755478574737771466443477069914070664457159874562246026231674202013525055051064032749275350905982802892471956172353456348747163465303302884619908731908096753154575131719129358212869729511062189039464751904900614685539733488960803754548627928530841064764065036079799777523666592044408376641702595881456975606363374738747468052431570879657918206353629078434589859560212766197636528957975011023399
			 * // public exponent: 65537 //
			 */

			try {
				extractedCert.setEncodedCertificate(cert.getEncoded());
			} catch (Exception ex) {
			}
			extractedCerts.add(extractedCert);
			i++;
		}
		return extractedCerts;
	}

	public void addCertificateChain(String host,
			X509Certificate[] certificateChain, SSLSocket socket,
			SSLSession session) {
		DatabaseManager.getInstance().getHostLock(host).lock();
		
		// certificates.put(host, certificateChain); // TODO: can be removed
		HostInfo hostInfo = DatabaseManager.getInstance().getHostInfo(host);
		if (hostInfo == null) {
			hostInfo = new HostInfo();
			hostInfo.setHostName(host);
			DatabaseManager.getInstance().addHostInfo(hostInfo);
		}
		
		// only add Certificate if we dont have any until now.
		if(hostInfo.getCert().size() == 0)
		{

			hostInfo.setCert(convertCertificate(certificateChain));

			// good to know:
			// http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLSocket.html
			// http://de.wikipedia.org/wiki/Transport_Layer_Security

			// Quote: http://en.wikipedia.org/wiki/Cipher_suite
			// "First, the client sends a cipher suite list, a list of the
			// cipher
			// suites that it supports, in order of preference. Then the server
			// replies with the cipher suite that it has selected from the
			// client
			// cipher suite list. (RFC 5246, p. 40) In order to test which TLS
			// ciphers that a server supports an SSL/TLS Scanner may be used."
			// Hence, the following information is pointless
			// socket.getEnabledProtocols();
			// socket.getEnabledCipherSuites();

			// extract more information:
			hostInfo.setNeedsClientAuth(socket.getNeedClientAuth());
			hostInfo.setWantsClientAuth(socket.getWantClientAuth());
			hostInfo.setSslProtocol(session.getProtocol());
			hostInfo.setCipherSuite(session.getCipherSuite());

			long certificateSize = 0L;
			for(X509Certificate cert : certificateChain)
			{
				try {
					certificateSize += cert.getEncoded().length;
				} catch (CertificateEncodingException e) {
					e.printStackTrace();
				}
			}
			hostInfo.setCertificateSize(certificateSize);
			
			hostInfo = DatabaseManager.getInstance().saveHostInfo(hostInfo);
		}
        DatabaseManager.getInstance().getHostLock(host).unlock();
		// Testing more information extraction:
		/*
		 * System.out.println("-------------------------------");
		 * System.out.println("SSLSession : cipherSuite: " +
		 * session.getCipherSuite());
		 * System.out.println("SSLSession : PeerHost: " +
		 * session.getPeerHost()); // www.kirchennetz.at
		 * System.out.println("SSLSession : PeerPort: " +
		 * session.getPeerPort()); // 443
		 * System.out.println("SSLSession : Protocol: " +
		 * session.getProtocol()); // TLSv1
		 * System.out.println("SSLSession : valuenames: " +
		 * Arrays.toString(session.getValueNames())); // []
		 * 
		 * System.out.println("SSLSocket : EnabledCipherSuites:   " +
		 * Arrays.toString(socket.getEnabledCipherSuites())); //
		 * [TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,...
		 * System.out.println("SSLSocket : SupportedCipherSuites: " +
		 * Arrays.toString(socket.getSupportedCipherSuites())); //
		 * [TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, ..
		 * System.out.println("SSLSocket : EnabledProtocols:   " +
		 * Arrays.toString(socket.getEnabledProtocols())); // [SSLv3, TLSv1]
		 * System.out.println("SSLSocket : SupportedProtocols: " +
		 * Arrays.toString(socket.getSupportedProtocols())); // [SSLv2Hello,
		 * SSLv3, TLSv1, TLSv1.1, TLSv1.2]
		 * System.out.println("SSLSocket : Need Client auth: " +
		 * socket.getNeedClientAuth()); // false
		 * System.out.println("SSLSocket : Want client auth: " +
		 * socket.getWantClientAuth()); // false //
		 */
	}

	// @Override
	// public String toString() {
	// StringBuilder s = new StringBuilder();
	// s = s.append("--------------- Certificates ---------------\n");
	// for (String host : certificates.keySet()) {
	// s = s.append("Host: ").append(host).append("\n");
	// X509Certificate[] certificate = certificates.get(host);
	// for (X509Certificate c : certificate) {
	//
	// s = s.append("  SigAlg:").append(c.getSigAlgName());
	// s = s.append(", type: ").append(c.getType());
	// s = s.append(", version: ").append(c.getVersion());
	// // s =
	// // s.append(", issuer: ").append(c.getIssuerDN().toString()); //
	// // same
	// s = s.append(", issuer: ").append(
	// c.getIssuerX500Principal().toString());
	// try {
	// s = s.append(", subject: ").append(
	// c.getSubjectX500Principal().toString());
	// s = s.append(", alt-subj: #").append(
	// c.getSubjectAlternativeNames().size());
	// // s =
	// //
	// s.append(", alt-issu: #").append(c.getIssuerAlternativeNames().size());
	// // // throws exception
	// } catch (Exception ex) {
	// s.append("###EXCEPTION###");
	// }
	// // s =
	// // s.append("\n     pub: ").append(c.getPublicKey().toString());
	//
	// // s =
	// //
	// s.append("\n-------------------------------------------------- full:");
	// // s = s.append(c.toString());
	// // s =
	// //
	// s.append("\n-------------------------------------------------- \n\n\n\n");
	// s = s.append("\n");
	// }
	// }
	// s = s.append("-------------------------------------------\n");
	// return s.toString();
	// }

}
