package at.chille.crawler.sslchecker;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Date;
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

	protected static final int queueSize = 100;

	/**
	 * The worker queue containing all SSL-hosts that shall be scanned by
	 * HttpsCheckerWorkers
	 */
	protected static ArrayBlockingQueue<String> hostQueue = new ArrayBlockingQueue<String>(
			queueSize);

	/**
	 * The result queue containing the results from the HttpsCheckerWorkers. It
	 * is processed by HttpsDbWorker.
	 */
	protected static ArrayBlockingQueue<HostSslInfo> resultQueue = new ArrayBlockingQueue<HostSslInfo>(
			queueSize);

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
		System.out.println("Needed parameters: ");
		System.out
				.println("\t rootFolder (it will contain intermediate crawl data)");
		System.out.println("\t numberOfWorkers (number of concurrent threads)");
		System.out
				.println("\t niceTimeWait (milliseconds to wait between each connection attempt to one host)");
		System.out
				.println("\t revisitDelay (milliseconds after which another scan to the same host is allowed");
		return;
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 4) {
			showHelp();
			return;
		}
		BufferedReader console = new BufferedReader(new InputStreamReader(
				System.in));

		System.out.println("Initializing SSL Config...");
		try {
			config.setTempFolder(args[0]);
			config.setNumWorkers(Integer.parseInt(args[1]));
			config.setTimesleep(Integer.parseInt(args[2]));
			config.setRevisitDelay(Long.parseLong(args[3]));
		} catch (Exception e) {
			showHelp();
			return;
		}

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
		for (String entry : StringFileReader.readLines("host-blacklist.txt")) {
			config.addBlacklist(entry);
		}

		// Try to initialize Database
		System.out.println("Initialize Database...");
		try {
			SSLDatabaseManager.getInstance();
			SSLDatabaseManager.getInstance().loadLastCrawlingSession();
		} catch (Exception ex) {
			ex.printStackTrace();
			throw ex;
		}

		System.out.println("Loading last SSL-Hosts...");
		SSLDatabaseManager.getInstance().loadLastHostSslInfos();
		
		// Hint: Exit here to test database schema only
		// System.exit(0);

		System.out.println("Loading queue with work...");
		Map<String, HostInfo> hosts;
		try {
			hosts = SSLDatabaseManager.getInstance().getAllHosts();
		} catch (Exception e) {
			System.err
					.println("Unable to fetch hosts. Did you run the HttpCrawler before?");
			return;
		}
		Thread producer = new Thread(new HttpsCheckerProducer(config,
				hostQueue, hosts));
		producer.start();

		System.out.println("Starting Workers...");
		stats = new HttpsCheckerStatistics();
		Thread dbWorker = new Thread(new HttpsDbWorker(resultQueue),
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
			checker.setFailureCallback(new LongCallback() {
				@Override
				public void Call(Long value) {
					stats.incrementFailures();
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
					printStats(hosts.size(), hostQueue.size());
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		}
		
		/**
		 * Now wait max. 5min for all running worker threads to finish.
		 */
		Long abortTime = (new Date()).getTime();
		Long timeout = 5 * 60 * 1000L;
		Long shortTimeout = 60 * 1000L;
		System.out.println("Controller: waiting max. 5 minutes for all workers to finish");
		// Now wait for all Workers to finish
		for (Thread t : workers) {
			// wait max. 5min for the worker threads to stop
			System.out.println("Controller: waiting max. 5 minutes for thread " + t.getId() + " to stop...");
			if((new Date()).getTime() - abortTime < timeout) {
				t.join(timeout);
			} 
			
			//If thread did not stop yet, interrupt it
			if(t.isAlive()) {
				System.err.println("Controller: Thread " + t.getId() + " seems dead. Interrupt it.");
				t.interrupt();
			}	
		}
		
		// signal dbWorker to stop, using an empty SslParseResult
		resultQueue.put(new HostSslInfo());

		System.out.println("Controller: waiting for DbWorker to stop...");
		if((new Date()).getTime() - abortTime < timeout) {
			dbWorker.join(timeout);
		} else {
			dbWorker.join(shortTimeout);
		}
		if(dbWorker.isAlive()) {
			System.err.println("Controller: DbWorker seems dead. Interrupt it.");
			dbWorker.interrupt();
			dbWorker.join();
		}
		
		System.out.println("Controller: all workers stopped");

		printStats(hosts.size(), 0);
		if(stats.getFailures() > 0) {
			System.err.println("Controller: not all hosts could be scanned. You can try to rerun HttpsChecker4j.");
		}
		
		System.out.println("Now closing...");
	}

	static void printStats(int numTotal, int currentlyPending) {
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
