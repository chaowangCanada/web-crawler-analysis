package at.chille.crawler.sslchecker.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.junit.Test;

import at.chille.crawler.sslchecker.ExecConfig;
import at.chille.crawler.sslchecker.ShellExecutor;
import at.chille.crawler.sslchecker.parser.SSLXmlParser;
import at.chille.crawler.sslchecker.parser.SslInfo;

public class SSLCheckerTest {

	private String xmlPath = "./sslscan/";
	private String xmlFile = xmlPath + "sslscan_test.xml";
	
	@Test
	public void TestShellExecutorBasic()
	{
		ExecConfig config = new ExecConfig();
		config.setExecutable("echo");
		config.setParam("$PWD");
		//config.setParam("Vieh!");
		ShellExecutor checker = new ShellExecutor(config);
		String result = checker.execute();
		System.out.println(result);
	}
	
	@Test
	public void TestSSLScan()
	{
		File file = new File(xmlFile);
		File path = new File(xmlPath);
		
		if(file.exists())
			assertTrue(file.delete());
		assertTrue(!file.exists());
		
		if(!path.exists())
			assertTrue(path.mkdir());
		
		
		ExecConfig config = new ExecConfig();
		config.setExecutable("sslscan");
		config.setRequiredVersion("1.8.2_t");
		config.setParam("--timesleep=10");
		config.setParam("--xml=" + xmlFile);
		config.setParam("tugraz.at");
		ShellExecutor checker = new ShellExecutor(config);
		assertTrue(checker.TestConfig());
		
		System.out.println("This test may need up to 1 minute");
		String result = checker.execute();
		System.out.println(result);
		assertTrue(file.exists());
	}
	
	@Test
	public void TestParsing()
	{
		File file = new File(xmlFile);
		assertTrue("execute TestSSLScan first", file.exists());
		
		try {
			FileInputStream streamIn   = new FileInputStream(xmlFile);
			SSLXmlParser parser = new SSLXmlParser();
			SslInfo result = parser.parse(streamIn);
			assertTrue(result != null);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
