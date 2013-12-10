package at.chille.sslchecker;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

import org.apache.http.conn.scheme.SchemeSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.log4j.Logger;

import at.chille.sslchecker.database.model.HostSSLInfo;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;

/**
 * @author chille
 * 
 */
public class HttpsCheckerController extends CrawlController {
	public HttpsCheckerController(CrawlConfig config,
			PageFetcher pageFetcher, RobotstxtServer robotstxtServer)
			throws Exception {
		super(config, pageFetcher, robotstxtServer);
	}

	protected static boolean resumable = true;
	protected static int threads = 1;

	protected static Logger logger = Logger
			.getLogger(HttpsCheckerController.class);


	@Override
	protected void cronJob() {
		super.cronJob();
		// deprecated, (5000 hosts -> 35 seconds
		// locking the database for this long time is extremely slow!
		// store directly, if something is changed in HostInfo!
		/*
		 * try { if (new Date().getTime() > lastStoreDatabase + storeInterval) {
		 * logger.info("Saving to database...");
		 * DatabaseManager.getInstance().saveSession();
		 * logger.info("Saved to database."); lastStoreDatabase = new
		 * Date().getTime(); } } catch (Exception ex) { ex.printStackTrace(); }
		 */
	}

  public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.out.println("Needed parameters: ");
			System.out
					.println("\t rootFolder (it will contain intermediate crawl data)");
			System.out
					.println("\t numberOfWorkers (number of concurrent threads)");
			System.out
					.println("\t niceTimeWait (milliseconds to wait between each connection attempt to one host)");
			return;
		}
		BufferedReader console = new BufferedReader(new InputStreamReader(
				System.in));

		while (true) {
			System.out
					.println("Do you want to make SSL checking resumable/resume SSL? (y/yes/n/no)");
			String command = console.readLine();
			if (command.toLowerCase().equals("y")
					|| command.toLowerCase().equals("yes")) {
				resumable = true;
				break;
			}
			if (command.toLowerCase().equals("n")
					|| command.toLowerCase().equals("no")) {
				resumable = false;
				break;
			}
		}

		System.out.println("Initializing SSL Config...");
		String crawlStorageFolder = args[0];
		threads = Integer.parseInt(args[1]);
		

		// Try to initialize Database
		logger.info("Initialize Database...");
//		try {
//			DatabaseManager.getInstance();
//			if (resumable) {
//				logger.info("Loading last SSL Session...");
//				DatabaseManager.getInstance().loadLastSSLSession();
//			}
//			if (DatabaseManager.getInstance().getCurrentSSLSession() == null) {
//				logger.info("Generate New SSL Session...");
//				DatabaseManager.getInstance().setNewSSLSession(
//						"Crawling Testing");
//			}
//
//			DatabaseManager.getInstance().saveSession();
//			// DatabaseManager.getInstance().tryAddingSomething();
//		} catch (Exception ex) {
//			ex.printStackTrace();
//			throw ex;
//		}
//
//		// Hint: Exit here to test database schema only
//		// System.exit(0);
//
//		logger.info("Setting up TrustStrategy and HostnameVerifier to catch the HTTPS Details...");
//		try {
//			TrustStrategy ts = new AllowAllTrustStrategy();
//			X509HostnameVerifier hv = new AllAllowHostNameVerifier();
//			SchemeSocketFactory httpsSocketFactory = new SSLSocketFactory(ts,
//					hv);
//			config.setHttpsSocketFactory(httpsSocketFactory);
//		} catch (Exception ex) {
//			System.err.println(ex.toString());
//		}
//
//		System.out.println("Crawling configuration:");
//		System.out.println(config);
//
//		// Instantiate the controller for this crawl.
//		logger.info("Init crawler...");
//		PageFetcher pageFetcher = new PageFetcher(config);
//		RobotstxtConfig robotstxtConfig = new RobotstxtConfig();
//		RobotstxtServer robotstxtServer = new RobotstxtServer(robotstxtConfig,
//				pageFetcher);
//		CrawlController controller = new HttpsCheckerController(config,
//				pageFetcher, robotstxtServer);
//
//		logger.info("Adding Seeds...");
//		for (String seed : StringFileReader.readLines("seeds.txt")) {
//			controller.addSeed(seed);
//			logger.info("Adding Seed: "+ seed);
//		}
//
//		// blocking operation:
//		logger.info("Starting Crawler...");
//		// controller.start(HttpAnalysisCrawler.class, numberOfCrawlers);
//		controller
//				.startNonBlocking(HttpAnalysisCrawler.class, numberOfCrawlers);
//		while (true) {
//			System.err
//					.println("Enter: 'abort' to exit process or 'status' for status: ");
//			String command = console.readLine();
//			if (command.toLowerCase().equals("abort")) {
//				break;
//			}
//			if (command.toLowerCase().equals("status")) {
//				try {
//					System.err.println("Queue Length: "
//							+ controller.getFrontier().getQueueLength());
//					System.err.println("Processed Pages: "
//							+ controller.getFrontier()
//									.getNumberOfProcessedPages());
//					// System.err.println("Assigned Pages: "
//					// + controller.getFrontier()
//					// .getNumberOfAssignedPages());
//				} catch (Exception ex) {
//					ex.printStackTrace();
//				}
//			}
//
//		}
//		controller.shutdown();
//		controller.waitUntilFinish();
//		// end of nonblocking version of crawler.
//
//		System.out.println("\n\n-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");
//		System.out.println("Finally storing the results to the database...");
//		DatabaseManager.getInstance().saveSession();
//		System.out.println("Done: You can abort this process.");
//
//		// Final output of crawler *IF* it finished:
//		System.out.println("\n\n");
//
//		Map<String, HostInfo> visitedHosts = DatabaseManager.getInstance()
//				.getCurrentCrawlingSession().getHosts();
//		System.out.println("Size of visited hosts: " + visitedHosts.size());
//		/*
//		 * Set<Map.Entry<String, HostInfo>> set = visitedHosts.entrySet(); for
//		 * (Map.Entry<String, HostInfo> host : set) { System.out.println("  " +
//		 * host.getKey() + " (" + host.getValue().getPages().size() + ")"); } //
//		 */
//
//		// System.out.println("\n\n");
//		// System.out.println(CertificateLogger.getInstance());
	}
}
