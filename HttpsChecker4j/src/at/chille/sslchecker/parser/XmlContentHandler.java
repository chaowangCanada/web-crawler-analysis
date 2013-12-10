package at.chille.sslchecker.parser;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class XmlContentHandler extends DefaultHandler {
	
	SslParseResult parseResult;
	
	public XmlContentHandler()
	{
		parseResult = new SslParseResult();
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
			suite.setCipher(attributes.getValue(attributes.getIndex("cipher")));
			
			if(status.equals("default"))
				parseResult.setPreferred(suite);
			else if(status.equals("accepted"))
				parseResult.setAccepted(suite);
			else if(status.equals("rejected"))
				parseResult.setRejected(suite);
			else if(status.equals("failed"))
				parseResult.setFailed(suite);
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
}
