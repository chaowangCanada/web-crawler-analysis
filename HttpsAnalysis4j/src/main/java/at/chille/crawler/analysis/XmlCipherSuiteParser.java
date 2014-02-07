package at.chille.crawler.analysis;

import java.io.InputStream;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class XmlCipherSuiteParser {
	
	public CipherSuiteRatingRepository parse(InputStream stream)
	{
		SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
	    try {
	        SAXParser saxParser = saxParserFactory.newSAXParser();
	        XmlCipherSuiteContentHandler handler = new XmlCipherSuiteContentHandler();
	        saxParser.parse(stream, handler);
	        return handler.getParseResult();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}
}