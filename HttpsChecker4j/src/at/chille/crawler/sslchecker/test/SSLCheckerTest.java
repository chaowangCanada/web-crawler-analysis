package at.chille.crawler.sslchecker.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Date;
import java.util.concurrent.ArrayBlockingQueue;

import org.junit.Test;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.sslchecker.ExecConfig;
import at.chille.crawler.sslchecker.HttpsDbWorker;
import at.chille.crawler.sslchecker.SSLDatabaseManager;
import at.chille.crawler.sslchecker.ShellExecutor;
import at.chille.crawler.sslchecker.parser.SSLXmlParser;

public class SSLCheckerTest {

	private String xmlPath = "./sslscan/";
	private String xmlFile = xmlPath + "sslscan_test.xml";
	private String host = "tugraz.at";
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
		config.setRequiredVersion("1.8.2");
		config.setParam("--timesleep=10");
		config.setParam("--xml=" + xmlFile);
		config.setParam(host);
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
			HostSslInfo result = parser.parse(streamIn);
			assertTrue(result != null);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void TestHttpsDbWorker()
	{
		File file = new File(xmlFile);
		assertTrue("execute TestSSLScan first", file.exists());
		HostSslInfo result = null;
		try {
			FileInputStream streamIn   = new FileInputStream(xmlFile);
			SSLXmlParser parser = new SSLXmlParser();
			result = parser.parse(streamIn);
			assertTrue(result != null);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return;
		}
		
		result.setHostSslName(host);
		result.setTimestamp((new Date()).getTime());
		
		SSLDatabaseManager.getInstance();
		SSLDatabaseManager.getInstance().loadLastCrawlingSession();
		
		//Fill up the processing queue
		ArrayBlockingQueue<HostSslInfo> resultQueue = new ArrayBlockingQueue<HostSslInfo>(2);
		resultQueue.add(result);
		resultQueue.add(new HostSslInfo());	//Terminator object
		
		//Start the worker
		HttpsDbWorker worker = new HttpsDbWorker(resultQueue);
		worker.run();
		
		//SSLDatabaseManager.getInstance().saveSession();
	}
}
