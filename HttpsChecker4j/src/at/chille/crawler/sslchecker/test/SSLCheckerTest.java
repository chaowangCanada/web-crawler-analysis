package at.chille.crawler.sslchecker.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.junit.Test;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.sslchecker.ExecConfig;
import at.chille.crawler.sslchecker.HttpsCheckerConfig;
import at.chille.crawler.sslchecker.HttpsCheckerProducer;
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
		config.setOmitRejectedCipherSuites(false);
		config.setOmitFailedCipherSuites(false);
		
		File file = new File(xmlFile);
		File path = new File(xmlPath);
		
		if(file.exists())
			assertTrue(file.delete());
		assertTrue(!file.exists());
		
		if(!path.exists())
			assertTrue(path.mkdir());
		
		ArrayBlockingQueue<String> hostQueue = new ArrayBlockingQueue<String>(2);
		ArrayBlockingQueue<HostSslInfo> resultQueue = new ArrayBlockingQueue<HostSslInfo>(6);
		
		config.setScanTLSv1_2(true);
		config.setScanTLSv1_1(false);
		config.setScanTLSv1(false);
		config.setScanSSLv3(false);
		config.setScanSSLv2(false);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		assertTrue(checkHostSslInfoResult(resultQueue, "TLSv1_2"));
		System.out.println("Worker Test TLSv1_2 succeeded.");
		System.out.println("Now write result into DB");
		resultQueue.add(new HostSslInfo());	//Terminator object
		(new HttpsDbWorker(config, resultQueue)).run();
		
		config.setScanTLSv1_2(false);
		config.setScanTLSv1_1(true);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		assertTrue(checkHostSslInfoResult(resultQueue, "TLSv1_1"));
		System.out.println("Worker Test TLSv1_1 succeeded.");
		System.out.println("Now write result into DB");
		resultQueue.add(new HostSslInfo());	//Terminator object
		(new HttpsDbWorker(config, resultQueue)).run();
		
		config.setScanTLSv1_1(false);
		config.setScanTLSv1(true);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		assertTrue(checkHostSslInfoResult(resultQueue, "TLSv1"));
		System.out.println("Worker Test TLSv1_0 succeeded.");
		System.out.println("Now write result into DB");
		resultQueue.add(new HostSslInfo());	//Terminator object
		(new HttpsDbWorker(config, resultQueue)).run();
		
		config.setScanTLSv1(false);
		config.setScanSSLv3(true);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		assertTrue(checkHostSslInfoResult(resultQueue, "SSLv3"));
		System.out.println("Worker Test SSLv3 succeeded.");
		System.out.println("Now write result into DB");
		resultQueue.add(new HostSslInfo());	//Terminator object
		(new HttpsDbWorker(config, resultQueue)).run();
		
		config.setScanSSLv3(false);
		config.setScanSSLv2(true);
		TestSslScanWorkerSingle(config, hostQueue, resultQueue);
		assertTrue(resultQueue.size() == 1);
		assertTrue(checkHostSslInfoResult(resultQueue, "SSLv2"));
		System.out.println("Worker Test SSLv2 succeeded.");
		System.out.println("Now write result into DB");
		resultQueue.add(new HostSslInfo());	//Terminator object
		(new HttpsDbWorker(config, resultQueue)).run();
	}
	
	private boolean checkHostSslInfoResult(Queue<HostSslInfo> resultQueue, String tlsVersion) {
		HostSslInfo currentInfo = resultQueue.peek();
		if(currentInfo == null)
			return false;
		
		for(CipherSuite cs : currentInfo.getAccepted()) {
			if(!cs.getTlsVersion().equalsIgnoreCase(tlsVersion))
				return false;
		}
		for(CipherSuite cs : currentInfo.getRejected()) {
			if(!cs.getTlsVersion().equalsIgnoreCase(tlsVersion))
				return false;
		}
		for(CipherSuite cs : currentInfo.getFailed()) {
			if(!cs.getTlsVersion().equalsIgnoreCase(tlsVersion))
				return false;
		}
		for(CipherSuite cs : currentInfo.getPreferred()) {
			if(!cs.getTlsVersion().equalsIgnoreCase(tlsVersion))
				return false;
		}
		return true;
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
	
	@Test
	public void TestBlacklist()
	{
		
		System.out.println("Loading last SSL-Hosts...");
		SSLDatabaseManager.getInstance();
		SSLDatabaseManager.getInstance().loadLastHostSslInfos();
		
		String[] hosts = {"google.at", "googlebat", "www.google.at", "ads.google.at", "www.google.com", "google-ads.com" };
		
		//filter all
		String[] bl1 = {".*"};
		assertTrue(applyBlacklist(hosts, bl1) == 0);
		
		//filter nothing
		assertTrue(applyBlacklist(hosts, new String[]{}) == hosts.length);
		
		//Only filter google.at correctly
		String[] bl2 = {"google", "at", "google\\.at"};
		assertTrue(applyBlacklist(hosts, bl2) == hosts.length-1);
		
		//Filter *google.at
		String[] bl3 = {".*google\\.at"};
		assertTrue(applyBlacklist(hosts, bl3) == hosts.length-3);
		
		//Filter *googl*
		String[] bl4 = {".*google.*"};
		assertTrue(applyBlacklist(hosts, bl4) == 0);
	}
	
	private int applyBlacklist(String[] hostList, String[] blacklist) {
		
		Map<String, HostInfo> hosts = new HashMap<String, HostInfo>();
		HostInfo dummy = new HostInfo();
	    dummy.setSslProtocol("SSL");
	    for(String h : hostList) {
	    	hosts.put(h, dummy);
	    }
		
	    HttpsCheckerConfig config = new HttpsCheckerConfig(0,  "sslscan", 0);
	    for(String b : blacklist) {
	    	config.addBlacklist(b);
	    }
	    
		ArrayBlockingQueue<String> hostQueue = new ArrayBlockingQueue<String>(hostList.length);
		(new HttpsCheckerProducer(config, hostQueue, hosts)).run();
		return hostQueue.size();
	}
}
