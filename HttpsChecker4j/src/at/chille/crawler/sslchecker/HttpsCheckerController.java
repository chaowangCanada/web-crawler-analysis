package at.chille.crawler.sslchecker;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

import org.apache.commons.io.FileUtils;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * Class HttpsCheckerController is the main class in HttpsChecker4j.
 * 
 * @author sammey
 * 
 */
public class HttpsCheckerController {
	public HttpsCheckerController() {
	}

	/**
	 * The worker queue containing all SSL-hosts that shall be scanned by
	 * HttpsCheckerWorkers
	 */
	protected static ArrayBlockingQueue<String> hostQueue;

	/**
	 * The result queue containing the results from the HttpsCheckerWorkers. It
	 * is processed by HttpsDbWorker.
	 */
	protected static ArrayBlockingQueue<HostSslInfo> resultQueue = new ArrayBlockingQueue<HostSslInfo>(100);

	/**
	 * The default configuration
	 */
	protected static HttpsCheckerConfig config = new HttpsCheckerConfig(1,
			"./sslscan/", 0);

	/**
	 * Statistics
	 */
	protected static HttpsCheckerStatistics stats;

	private static void showHelp() {
		System.out.println("          HTTPS Checker utility");
		System.out.println("                version 1.0");
		System.out.println("");
		System.out.println("Options - default parameters are in (brackets)");
		System.out.println("hosts=<file>            contains one host per line to scan. ");
		System.out.println("                        If this parameter is omitted, hosts are taken from the database");
		System.out.println("blacklist=<file>        contains one regex per line to blacklist hosts (blacklist.txt)");
		System.out.println("temp=<folder>           folder for intermediate scan data (temp)");
		System.out.println("workers=<integer>       number of concurrent scanning threads (5)");
		System.out.println("niceWait=<millisec>     time to wait between each connection attempt to one host (1000)");
		System.out.println("revisitDelay=<millisec> timespan after which another scan to the same host is allowed (0)");
		System.out.println("tlsv1_2=<true|false>    scan TLSv1.2 ciphersuites (true)");
		System.out.println("tlsv1_1=<true|false>    scan TLSv1.1 ciphersuites (true)");
		System.out.println("tlsv1=<true|false>      scan TLSv1.0 ciphersuites (true)");
		System.out.println("sslv3=<true|false>      scan SSLv3 ciphersuites (false)");
		System.out.println("sslv2=<true|false>      scan SSLv2 ciphersuites (false)");
		System.out.println("omitRejected            don't store rejected ciphersuites in database");
		System.out.println("omitFailed              don't store failed ciphersuites in database");
		System.out.println("--help                  show this help page");
		return;
	}

	public static void main(String[] args) throws Exception {
		//Initialize default configuration
		String blacklistFile = "blacklist.txt";
		config.setHostFile("");
		config.setTempFolder("temp");
		config.setNumWorkers(5);
		config.setTimesleep(1000);
		config.setRevisitDelay(0L);
		config.setScanTLSv1_2(true);
		config.setScanTLSv1_1(true);
		config.setScanTLSv1(true);
		config.setScanSSLv3(false);
		config.setScanSSLv2(false);
		config.setOmitRejectedCipherSuites(false);
		config.setOmitFailedCipherSuites(false);
		
		BufferedReader console = new BufferedReader(new InputStreamReader(
				System.in));

		System.out.println("Initializing SSL Config...");
		try {
			for(String a : args) {
				if(a.equals("-h") || a.equals("-help") || a.equals("--help")) {
					showHelp();
					return;
				} else if (a.startsWith("hosts=")) {
					config.setHostFile(a.replace("hosts=", ""));
				} else if (a.startsWith("blacklist=")) {
					blacklistFile = a.replace("blacklist=", "");
				} else if(a.startsWith("temp=")) {
					config.setTempFolder(a.replace("temp=", ""));
				} else if (a.startsWith("workers=")) {
					config.setNumWorkers(Integer.parseInt(a.replace("workers=", "")));
				} else if (a.startsWith("niceWait=")) {
					config.setTimesleep(Integer.parseInt(a.replace("niceWait=", "")));
				} else if (a.startsWith("revisitDelay=")) {
					config.setRevisitDelay(Long.parseLong(a.replace("revisitDelay=",  "")));
				} else if (a.startsWith("tlsv1_2=")) {
					config.setScanTLSv1_2(Boolean.parseBoolean(a.replace("tlsv1_2=", "")));
				} else if (a.startsWith("tlsv1_1=")) {
					config.setScanTLSv1_1(Boolean.parseBoolean(a.replace("tlsv1_1=", "")));
				} else if (a.startsWith("tlsv1=")) {
					config.setScanTLSv1(Boolean.parseBoolean(a.replace("tlsv1=", "")));
				} else if (a.startsWith("sslv3=")) {
					config.setScanSSLv3(Boolean.parseBoolean(a.replace("sslv3=", "")));
				} else if (a.startsWith("sslv2=")) {
					config.setScanSSLv2(Boolean.parseBoolean(a.replace("sslv2=", "")));
				} else if (a.startsWith("omitRejected")) {
					config.setOmitRejectedCipherSuites(true);
				} else if (a.startsWith("omitFailed")) {
					config.setOmitFailedCipherSuites(true);
				}
			}
		} catch (Exception e) {
			showHelp();
			return;
		}
		
		/**
		 * about 220 ciphersuites, round up to 300
		 * (scantime + timesleep) milliseconds per ciphersuite
		 * scantime is estimated with 200ms
		 * multiplied with number of TLS versions
		 */
		int num = 0;
		if(config.isScanTLSv1_2()) {
			num++;
		}
		if(config.isScanTLSv1_1()) {
			num++;
		}
		if(config.isScanTLSv1()) {
			num++;
		}
		if(config.isScanSSLv3()) {
			num++;
		}
		if(config.isScanSSLv2()) {
			num++;
		}
		config.setHostTimeout(300L * (100 + config.getTimesleep()) * num);
		
		System.out.print("Testing SSL Checker...");
		boolean sslWorking = config.testSslChecker();
		if (!sslWorking) {
			System.out.println("failed");
			return;
		}
		System.out.println("passed");

		System.out.println("Preparing temporary folder...");
		if (!prepareTempFolder())
			return;

		System.out.println("Importing blacklist...");
		for (String entry : StringFileReader.readLines(blacklistFile)) {
			config.addBlacklist(entry);
		}

		System.out.println("");
		System.out.println(config.toString());
		System.out.println("Hit y to continue...");
		if(System.in.read() != 'y')
			return;
		
		hostQueue = new ArrayBlockingQueue<String>(config.getNumWorkers());
		System.out.println("Loading last SSL-Hosts...");
		SSLDatabaseManager.getInstance();
		SSLDatabaseManager.getInstance().loadLastHostSslInfos();
		
		// Hint: Exit here to test database schema only
		// System.exit(0);

		System.out.println("Loading queue with work...");
		Map<String, HostInfo> hosts;
		try {
			if(config.getHostFile() != null && config.getHostFile().length() > 0) {
				hosts = new HashMap<String, HostInfo>(); 
			    List<String> hostsFromFile = StringFileReader.readLines(config.getHostFile());
			    HostInfo dummy = new HostInfo();
			    dummy.setSslProtocol("SSL");
			    for(String h : hostsFromFile) {
			    	hosts.put(h,  dummy);
			    }
			} else {
				System.out.println("Load hosts from Database...");
				SSLDatabaseManager.getInstance().loadLastCrawlingSession();
				hosts = SSLDatabaseManager.getInstance().getAllHosts();
			}
		} catch (Exception e) {
			System.err
					.println("Unable to fetch hosts. Did you run the HttpCrawler before?");
			showHelp();
			return;
		}
		Thread producer = new Thread(new HttpsCheckerProducer(config,
				hostQueue, hosts));
		producer.start();

		System.out.println("Starting Workers...");
		stats = new HttpsCheckerStatistics();
		Thread dbWorker = new Thread(new HttpsDbWorker(config, resultQueue),
				"HttpsDbWorker");
		dbWorker.start();

		ArrayList<Thread> workers = new ArrayList<Thread>();
		for (int i = 0; i < config.getNumWorkers(); i++) {
			HttpsCheckerWorker checker = new HttpsCheckerWorker(config,
					hostQueue, resultQueue);
			checker.setSuccessCallback(new LongCallback() {
				@Override
				public void Call(Long value) {
					stats.incrementSuccesses();
				}
			});
			checker.setFailureCallback(new StringCallback() {
				@Override
				public void Call(String value) {
					stats.incrementFailures();
					stats.logFailure(value);
				}
			});
			checker.setRoundTimeCallback(new LongCallback() {
				@Override
				public void Call(Long value) {
					stats.addPageScanSpeed(value);
				}
			});

			Thread t = new Thread(checker, "HttpsCheckerWorker");
			t.start();
			workers.add(t);
		}

		// Enable command interface
		while (true) {
			System.err
					.println("Enter: 'abort' to exit process or 'status' for status: ");
			String command = console.readLine();
			if (command.toLowerCase().equals("abort")
					|| command.toLowerCase().equals("exit")
					|| command.toLowerCase().equals("quit")) {

				System.err.println("Controller: signaling workers to stop.");
				producer.interrupt();
				break;
			}
			if (command.toLowerCase().equals("status")) {
				try {
					printStats(hosts.size(), hostQueue.size(), hostQueue.size() + hostQueue.remainingCapacity());
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		}
		
		/**
		 * Now wait max. hostTimeout for all running worker threads to finish.
		 */
		
		Long abortTime = (new Date()).getTime();
		Long shortTimeout = config.getHostTimeout() / 10;
		Long seconds = config.getHostTimeout() / 1000;
		System.out.println("Controller: waiting max. " + seconds + " seconds for all workers to finish");
		// Now wait for all Workers to finish
		for (Thread t : workers) {
			// wait max. 5min for the worker threads to stop
			System.out.println("Controller: waiting max. " + seconds + " for thread " + t.getId() + " to stop...");
			if((new Date()).getTime() - abortTime < config.getHostTimeout()) {
				t.join(config.getHostTimeout());
			} 
			
			//If thread did not stop yet, interrupt it
			if(t.isAlive()) {
				System.err.println("Controller: Thread " + t.getId() + " seems dead. Interrupt it.");
				t.interrupt();
			}	
		}
		
		// signal dbWorker to stop, using an empty result
		resultQueue.put(new HostSslInfo());

		System.out.println("Controller: waiting for DbWorker to stop...");
		if((new Date()).getTime() - abortTime < config.getHostTimeout()) {
			dbWorker.join(config.getHostTimeout());
		} else {
			dbWorker.join(shortTimeout);
		}
		if(dbWorker.isAlive()) {
			System.err.println("Controller: DbWorker seems dead. Interrupt it.");
			dbWorker.interrupt();
			dbWorker.join();
		}
		
		System.out.println("Controller: all workers stopped");

		printStats(hosts.size(), 0, 0);
		if(stats.getFailures() > 0) {
			System.err.println("Controller: not all hosts could be scanned. You can try to rerun HttpsChecker4j.");
		}
		
		System.out.println("Now closing...");
	}

	static void printStats(int numTotal, int currentlyPending, int queueSize) {
		System.err.println("Status Report:");
		System.err.println("Total no. of hosts: " + numTotal);
		System.err.println("SSL-Hosts finished: " + stats.getSuccesses());
		System.err.println("SSL-Hosts failed:   " + stats.getFailures());
		System.err.println("Av. seconds/host:   " + stats.getAveragePageScanSpeed());
		System.err.println("Fastest host (sec): " + stats.getFastestPageScanSpeed());
		System.err.println("Slowest host (sec): " + stats.getSlowestScanSpeed());
		System.err.println("Pages per minute:   " + stats.getPagesPerMinute());
		if (currentlyPending > 0) {
			System.err.println("Working Queue: " + currentlyPending + "/"
					+ queueSize);
		}
	}

	/**
	 * Setup a temporary folder for sslscan output files. The An existing folder
	 * is emptied first.
	 * 
	 * @return true on success
	 */
	static boolean prepareTempFolder() {
		try {
			File folder = new File(config.getTempFolder());
			FileUtils.deleteDirectory(folder);

			folder = new File(config.getTempFolder());
			folder.mkdirs();
			folder.deleteOnExit();
			return true;
		} catch (IOException e) {
			System.err.println(e.getMessage());
			return false;
		}
	}
}
