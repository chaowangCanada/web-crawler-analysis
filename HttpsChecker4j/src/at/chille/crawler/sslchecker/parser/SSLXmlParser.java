package at.chille.crawler.sslchecker.parser;

import java.io.InputStream;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.sslchecker.parser.XmlContentHandler;

public class SSLXmlParser {
	
	public HostSslInfo parse(InputStream stream)
	{
		SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
	    try {
	        SAXParser saxParser = saxParserFactory.newSAXParser();
	        XmlContentHandler handler = new XmlContentHandler();
	        saxParser.parse(stream, handler);
	        return handler.getParseResult();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}
}
