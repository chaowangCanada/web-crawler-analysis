package at.chille.sslchecker.parser;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;





import org.xml.sax.SAXException;


//import org.apache.tika.metadata.Metadata;
//import org.apache.tika.parser.ParseContext;
//import org.apache.tika.parser.xml.XMLParser;
import at.chille.sslchecker.parser.XmlContentHandler;

public class SSLXmlParser {

//	private XMLParser xmlParser;
//	private ParseContext parseContext;
//	public SSLXmlParser() {
//			xmlParser = new XMLParser();
//			parseContext = new ParseContext();
//		}
//	
//	public void parse(InputStream stream)
//	{
//			Metadata metadata = new Metadata();
//			XmlContentHandler contentHandler = new XmlContentHandler();
//			try {
//				xmlParser.parse(stream, contentHandler, metadata, parseContext);
//			} catch (Exception e) {
//				System.err.println("Error while XML-parsing: " + e.getMessage());
//				return;
//			}
//
////			if (page.getContentCharset() == null) {
////				page.setContentCharset(metadata.get("Content-Encoding"));
////			}
//			
//			
//	}
	
	public void parse(InputStream stream)
	{
		SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
	    try {
	        SAXParser saxParser = saxParserFactory.newSAXParser();
	        XmlContentHandler handler = new XmlContentHandler();
	        saxParser.parse(stream, handler);
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}
}
