package at.chille.crawler.sslchecker.parser;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import at.chille.crawler.database.model.sslchecker.CipherSuite;

public class XmlContentHandler extends DefaultHandler {
	
	private SslInfo parseResult;
	
	public XmlContentHandler()
	{
		parseResult = new SslInfo();
	}
	
	@Override
	public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
		//System.out.println("Start element: " + qName);
		
		if(qName.equals("cipher") || qName.equals("defaultcipher"))
		{
			String status;
			CipherSuite suite = new CipherSuite();
			if(qName.equals("cipher"))
			{
				status = attributes.getValue(attributes.getIndex("status"));
			}
			else
			{
				status = "default";
			}
			suite.setTlsVersion(attributes.getValue(attributes.getIndex("sslversion")));
			suite.setBits(Integer.parseInt(attributes.getValue(attributes.getIndex("bits"))));
			suite.setCipherSuite(attributes.getValue(attributes.getIndex("cipher")));
			
			if(status.equals("default"))
				getParseResult().setPreferred(suite);
			else if(status.equals("accepted"))
				getParseResult().setAccepted(suite);
			else if(status.equals("rejected"))
				getParseResult().setRejected(suite);
			else if(status.equals("failed"))
				getParseResult().setFailed(suite);
			else
				System.err.println("XmlContentHandler: cipher-status " + status + " not supported!");	
		}
	}

	@Override
	public void endElement(String uri, String localName, String qName) throws SAXException {
		//System.out.println("End element");
	}

	@Override
	public void characters(char ch[], int start, int length) throws SAXException {
			//System.out.println("Content>>"+new String(ch, start, length) + "<<");
	}

	public SslInfo getParseResult() {
		return parseResult;
	}
}
