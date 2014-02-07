package at.chille.crawler.analysis.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Map.Entry;

import org.junit.Test;

import at.chille.crawler.analysis.CipherSuiteRatingRepository;
import at.chille.crawler.analysis.Rating;
import at.chille.crawler.analysis.XmlCipherSuiteParser;

public class HttpsAnalysisTests {

	private String xmlFile = "CipherSuiteRating.xml";
	
	@Test
	public void CipherSuiteRatingParserTest() {
		File file = new File(xmlFile);
		assertTrue("Create a file CipherSuiteRating.xml first!", file.exists());
		
		try {
			FileInputStream streamIn   = new FileInputStream(xmlFile);
			XmlCipherSuiteParser parser = new XmlCipherSuiteParser();
			CipherSuiteRatingRepository result = parser.parse(streamIn);
			assertTrue(result != null && result.getCipherRating() != null && result.getCipherRating().entrySet().size() > 0);
			System.out.println("Example output of BulkCiphers:");
			for(Entry<String, Rating> e : result.getCipherRating().entrySet()) {
				System.out.println(e.getKey() + ": " + e.getValue().getValue() + "pts, " + e.getValue().getDescription());
			}
				
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
}
