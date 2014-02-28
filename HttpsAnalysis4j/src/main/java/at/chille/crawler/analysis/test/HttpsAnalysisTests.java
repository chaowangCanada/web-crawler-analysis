package at.chille.crawler.analysis.test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import at.chille.crawler.analysis.CipherSuiteRatingRepository;
import at.chille.crawler.analysis.SslRating;
import at.chille.crawler.analysis.XmlCipherSuiteParser;
import at.chille.crawler.database.model.sslchecker.CipherSuite;

public class HttpsAnalysisTests {

	private String xmlFile = "CipherSuiteRating.xml";
	
	@Test
	public void CipherSuiteRatingParserValidTests() {
		File file = new File(xmlFile);
		assertTrue("Create a file CipherSuiteRating.xml first!", file.exists());
		Map<String, SslRating> ratingList = new HashMap<String, SslRating>();
		
		try {
			FileInputStream streamIn    = new FileInputStream(xmlFile);
			XmlCipherSuiteParser parser = new XmlCipherSuiteParser();
			
		  parser.parse(streamIn);
		  
		  CipherSuite cs = new CipherSuite();
		  cs.setBits(0);
		  cs.setCipherSuite("NULL-NULL-NULL");
		  cs.setTlsVersion("SSLv3");
		  ratingList.put(cs.getCipherSuite(), CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("NULL-NULL-MD5");
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setBits(128);
		  cs.setCipherSuite("CAMELLIA128-SHA");
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("ECDHE-ECDSA-AES256-GCM-SHA384");
		  cs.setBits(256);
		  cs.setTlsVersion("TLSv1");
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("EXP-EDH-DSS-DES-CBC-SHA");
		  cs.setBits(40);
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("DES-CBC3-SHA");
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("NULL-SHA");
		  cs.setBits(0);
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("SRP-DSS-AES-256-CBC-SHA");
		  cs.setBits(256);
		  cs.setTlsVersion("SSLv3");
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("ADH-AES256-SHA256");
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  cs.setCipherSuite("SEED-SHA");
		  cs.setBits(56);
		  ratingList.put(cs.getCipherSuite(),CipherSuiteRatingRepository.getInstance().getCipherRating(cs));
		  
		  for (Map.Entry<String, SslRating> r : ratingList.entrySet()) {
	      assertTrue(r != null);
	      System.out.println("Output of TestRating: Value is " + r.getValue().getValue() + ", "
	          + "Cipher is " + r.getKey() + " and Description is: " + r.getValue().getDescription());
	    }
		  
		} catch (Exception e) {
		    System.out.println(e.getMessage());
		    fail("Fail during parsing occured!");
			  //e.printStackTrace();
		}
	}
	
	@Test 
	public void CipherSuiteRatingParserInvalidTests() {
	  
	  File file = new File(xmlFile);
    assertTrue("Create a file CipherSuiteRating.xml first!", file.exists());
    @SuppressWarnings("unused")
    SslRating testRating;
    
    try {
      FileInputStream streamIn   = new FileInputStream(xmlFile);
      XmlCipherSuiteParser parser = new XmlCipherSuiteParser();
      parser.parse(streamIn);
    } catch (Exception e) {
        System.out.println(e.getMessage());
        //e.printStackTrace();
        fail("Failed to parse xml-file");
    }
    
    CipherSuite cs = new CipherSuite();
    cs.setBits(0);
    cs.setTlsVersion("SSLv3");
    
    // wrong cipher suite names
    try {
      cs.setCipherSuite("NULL-NULL-MD55");
      testRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
      fail("getCipherRating(\"NULL-NULL-MD55\") should thow an exception!!");
    }catch (Exception e) {
      System.out.println(e.getMessage());
    }
    
    try {
      cs.setCipherSuite("NULL-AEES256-MD5");
      testRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
      fail("getCipherRating(\"NULL-AEES256-MD5\") should thow an exception!!");
    }catch (Exception e) {
      System.out.println(e.getMessage());
    }
    
    try {
      cs.setCipherSuite("SAMMEY-AES128-SHA");
      testRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
      fail("getCipherRating(\"SAMMEY-AES128-SHA\") should thow an exception!!");
    }catch (Exception e) {
      System.out.println(e.getMessage());
    }
    
    // wrong tls versions
    cs.setCipherSuite("NULL-NULL-MD5");
    try {
      cs.setTlsVersion("TLLvXY");
      testRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
      fail("getCipherRating(\"NULL-NULL-MD55\") should thow an exception!!");
    }catch (Exception e) {
      System.out.println(e.getMessage());
    }
    
    try {
      cs.setTlsVersion("SSLvv3");
      testRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
      fail("getCipherRating(\"NULL-AEES256-MD5\") should thow an exception!!");
    }catch (Exception e) {
      System.out.println(e.getMessage());
    }
    
    // wrong amount of bits (not possible; the second case at least for now)
    cs.setTlsVersion("TLSv1");
    try {
      cs.setBits(-400);
      testRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
      fail("getCipherRating(\"NULL-NULL-MD55\") should thow an exception!!");
    }catch (Exception e) {
      System.out.println(e.getMessage());
    }
    
    try {
      cs.setBits(2147483646);
      testRating = CipherSuiteRatingRepository.getInstance().getCipherRating(cs);
      fail("getCipherRating(\"NULL-AEES256-MD5\") should thow an exception!!");
    }catch (Exception e) {
      System.out.println(e.getMessage());
    }
	}
}
