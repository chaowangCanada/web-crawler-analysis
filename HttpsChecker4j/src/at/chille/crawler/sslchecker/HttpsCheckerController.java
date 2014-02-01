package at.chille.crawler.sslchecker;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

import org.apache.commons.io.FileUtils;
import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * @author chille
 * 
 */
public class HttpsCheckerController {
	public HttpsCheckerController() {
	}

	protected static final int queueSize = 1000;
	protected static int numWorkers = 1;
	protected static ArrayBlockingQueue<String> hostQueue = new ArrayBlockingQueue<String>(queueSize);
    protected static ArrayBlockingQueue<HostSslInfo> resultQueue = new ArrayBlockingQueue<HostSslInfo>(queueSize);
	protected static HttpsCheckerConfig config = new HttpsCheckerConfig(
			"./sslscan/", 0);

	protected static int finished = 0;
	public static synchronized void incrementFinishedCounter()
	{
		finished++;
	}
	
	private static void showHelp() {
		System.out.println("Needed parameters: ");
		System.out
				.println("\t rootFolder (it will contain intermediate crawl data)");
		System.out.println("\t numberOfWorkers (number of concurrent threads)");
		System.out
				.println("\t niceTimeWait (milliseconds to wait between each connection attempt to one host)");
		return;
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 3) {
			showHelp();
			return;
		}
		BufferedReader console = new BufferedReader(new InputStreamReader(
				System.in));

		System.out.println("Initializing SSL Config...");
		try {
			config.setTempFolder(args[0]);
			numWorkers = Integer.parseInt(args[1]);
			config.setTimesleep(Integer.parseInt(args[2]));
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

		// Hint: Exit here to test database schema only
		// System.exit(0);

		System.out.println("Starting Workers...");
		Thread dbWorker = new Thread(new HttpsDbWorker(resultQueue), "HttpsDbWorker");
		dbWorker.start();
		
		ArrayList<Thread> workers = new ArrayList<Thread>();
		for (int i = 0; i < numWorkers; i++) {
			HttpsCheckerWorker checker = new HttpsCheckerWorker(config, hostQueue, resultQueue);
			Thread t = new Thread(checker, "HttpsCheckerWorker");
			t.start();
			workers.add(t);
		}

		System.out.println("Loading queue with work...");
		Map<String, HostInfo> hosts;
		try {
			hosts = SSLDatabaseManager.getInstance()
					.getAllHosts();
		} catch (Exception e) {
			System.err.println("Unable to fetch hosts. Did you run the HttpCrawler before?");
			return;
		}
		for (String host : hosts.keySet()) {
			if (!shouldVisitForInspection(host))
				System.out.println("Filtering host " + host);
			else {
				HostInfo hostInfo = hosts.get(host);
				if (hostInfo != null && hostInfo.getSslProtocol() != null) {
					String protocol = hostInfo.getSslProtocol();
					if (protocol != null && protocol != "") {
						// System.out.println(protocol + ":" + host);
						System.out
								.println("Controller: enqueuing host " + host);
						hostQueue.add(host);
					}
				}
			}
		}

		for (int i = 0; i < numWorkers; i++) {
			hostQueue.add("stop");
		}

		while (true) {
			System.err
					.println("Enter: 'abort' to exit process or 'status' for status: ");
			String command = console.readLine();
			if (command.toLowerCase().equals("abort")
					|| command.toLowerCase().equals("exit")
					|| command.toLowerCase().equals("quit")) {
				
				//remove pending hosts from queue and signal stop
				System.out.println("Controller: clearing working queue");
				hostQueue.clear();
				for (int i = 0; i < numWorkers; i++) {
					hostQueue.add("stop");
				}
				break;
			}
			if (command.toLowerCase().equals("status")) {
				try {
					int numTotal = hosts.size();
					int currentlyPending = hostQueue.size();
					
					System.err.println("Status Report:");
					System.err.println("Total number of hosts:\t" + numTotal);
					System.err.println("SSL-Hosts finished:\t"+ finished);
					System.err.println("Working Queue: " + currentlyPending + "/" + queueSize);
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		}
		
		System.out.println("Controller: waiting for all workers to finish");
		//Now wait for all Workers to finish
		for(Thread t : workers)
		{
			//wait max. 5min for each thread to stop
			t.join(5*60*1000);
		}
		
		//signal dbWorker to stop, using an empty SslParseResult
		resultQueue.add(new HostSslInfo());
		
		//wait max. 5min for each thread to stop
		dbWorker.join(5*60*1000);
				
		System.out.println("Now closing...");
	}

	/**
	 * Decides if the given HostInfo should be visited for SSL-checking. Returns
	 * true if the host was not visited yet and the host is not on the
	 * blacklist.
	 * 
	 * @param host
	 *            to check
	 * @return true if the URL should be visited
	 */
	static boolean shouldVisitForInspection(String host) {
		for (String regex : config.getBlacklist()) {
			if (host.matches(regex))
				return false;
		}
		return true;
	}

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
