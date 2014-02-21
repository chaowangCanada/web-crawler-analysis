package at.chille.crawler.sslchecker.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Date;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.junit.Test;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.sslchecker.ExecConfig;
import at.chille.crawler.sslchecker.HttpsCheckerConfig;
import at.chille.crawler.sslchecker.HttpsCheckerWorker;
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
		HttpsCheckerConfig config = new HttpsCheckerConfig(0, "", 0);
		config.setOmitRejectedCipherSuites(true);
		config.setOmitFailedCipherSuites(true);
		
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
		HttpsDbWorker worker = new HttpsDbWorker(config, resultQueue);
		worker.run();
		
		//SSLDatabaseManager.getInstance().saveSession();
	}
	
	@Test
	public void TestSSLScanWorker()
	{
		HttpsCheckerConfig config = new HttpsCheckerConfig(1, "sslscan", 0);
		config.setOmitRejectedCipherSuites(true);
		config.setOmitFailedCipherSuites(true);
		
		File file = new File(xmlFile);
		File path = new File(xmlPath);
		
		if(file.exists())
			assertTrue(file.delete());
		assertTrue(!file.exists());
		
		if(!path.exists())
			assertTrue(path.mkdir());
		
		ArrayBlockingQueue<String> hostQueue = new ArrayBlockingQueue<String>(2);
		ArrayBlockingQueue<HostSslInfo> resultQueue = new ArrayBlockingQueue<HostSslInfo>(6);
		
		config.setScanTLSv1(false);
		config.setScanSSLv3(false);
		config.setScanSSLv2(true);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		System.out.println("Worker Test SSLv2 succeeded.");
		
		config.setScanSSLv3(true);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		System.out.println("Worker Test SSLv2 and SSLv3 succeeded.");
		
		config.setScanTLSv1(true);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		
		System.out.println("Worker Test TLSv1, SSLv3 and SSLv2 succeeded.");
		System.out.println("Now write result into DB");
		
		resultQueue.add(new HostSslInfo());	//Terminator object
		HttpsDbWorker worker = new HttpsDbWorker(config, resultQueue);
		worker.run();
	}
	
	public void TestSslScanWorkerSingle(HttpsCheckerConfig config, 
			BlockingQueue<String> hostQueue, 
			BlockingQueue<HostSslInfo> resultQueue)
	{
		try {
			hostQueue.clear();
			resultQueue.clear();
			hostQueue.put(host);
			hostQueue.put("stop");
			(new HttpsCheckerWorker(config, hostQueue, resultQueue)).run();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			assertTrue(false);
		}
	}
}
