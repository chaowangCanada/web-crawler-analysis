package at.chille.crawler.analysis;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

public class XmlCipherSuiteContentHandler extends DefaultHandler {

	private CipherSuiteRatingRepository parseResult;
	private String content;
	private String name;
	private Integer rating;

	public XmlCipherSuiteContentHandler() {
		parseResult = new CipherSuiteRatingRepository();
	}

	@Override
	public void startElement(String uri, String localName, String qName,
			Attributes attributes) throws SAXException {
		try {
			content = "";
			if (qName.equals("Handshake") || qName.equals("BulkCipher")
					|| qName.equals("Hash")) {
				name = attributes.getValue("name");
				rating = Integer.parseInt(attributes.getValue("rating"));
				if (name == null || rating == null) {
					throw new Exception("<" + name
							+ ">: XML-attribute name or rating missing");
				}
			}
		} catch (Exception e) {
			System.err.println("SAX-Parsing error: " + e.getMessage());
		}
	}

	@Override
	public void endElement(String uri, String localName, String qName)
			throws SAXException {
		try {
			if (qName.equals("Handshake")) {
				parseResult.addHandshakeRating(name, new Rating(rating, content));
			} else if (qName.equals("BulkCipher")) {
				parseResult.addCipherRating(name, new Rating(rating, content));
			} else if (qName.equals("Hash")) {
				parseResult.addHashRating(name, new Rating(rating, content));
			}
		} catch (Exception e) {
			System.err.println("SAX-Parsing error: " + e.getMessage());
		}
	}

	@Override
	public void characters(char ch[], int start, int length)
			throws SAXException {
		String cstring = new String(ch);
		content += cstring.substring(start, start + length);
	}

	public CipherSuiteRatingRepository getParseResult() {
		return parseResult;
	}
}
