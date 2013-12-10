package at.chille.sslchecker.test;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;

import org.junit.Test;

import at.chille.sslchecker.ExecConfig;
import at.chille.sslchecker.SSLChecker;
import at.chille.sslchecker.parser.SSLXmlParser;

public class SSLCheckerTest {

	private String xmlPath = "./sslscan/sslscan_test.xml";
	@Test
	public void TestSSLCheckerBasic()
	{
		ExecConfig config = new ExecConfig();
		config.setExecutable("echo");
		config.setParam("$PWD");
		//config.setParam("Vieh!");
		SSLChecker checker = new SSLChecker(config);
		String result = checker.execute();
		System.out.println(result);
	}
	
	@Test
	public void TestSSLScan()
	{
		ExecConfig config = new ExecConfig();
		config.setExecutable("sslscan");
		config.setRequiredVersion("1.8.2");
		config.setParam("--xml=" + xmlPath);
		config.setParam("tugraz.at");
		SSLChecker checker = new SSLChecker(config);
		assertTrue(checker.TestConfig());
		
		String result = checker.execute();
		System.out.println(result);
	}
	
	@Test
	public void TestParsing()
	{
		try {
			FileInputStream streamIn   = new FileInputStream(xmlPath);
			SSLXmlParser parser = new SSLXmlParser();
			parser.parse(streamIn);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
