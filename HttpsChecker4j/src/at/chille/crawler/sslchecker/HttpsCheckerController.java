package at.chille.crawler.sslchecker;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

import org.apache.log4j.Logger;

import at.chille.crawler.database.model.HostInfo;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;

/**
 * @author chille
 * 
 */
public class HttpsCheckerController  {
	public HttpsCheckerController() {
	}

	protected static boolean resumable = true;
	protected static int workers = 1;

	protected static Logger logger = Logger
			.getLogger(HttpsCheckerController.class);


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
		workers = Integer.parseInt(args[1]);
		

		// Try to initialize Database
		logger.info("Initialize Database...");
		try {
			SSLDatabaseManager.getInstance();
			SSLDatabaseManager.getInstance().loadLastCrawlingSession();
			
			if (resumable) {
				logger.info("Loading last SSL Session...");
				SSLDatabaseManager.getInstance().loadLastSslSession();
			}
			if (SSLDatabaseManager.getInstance().getCurrentSslSession() == null) {
				logger.info("Generate New SSL Session...");
				SSLDatabaseManager.getInstance().setNewSslSession(
						"Crawling Testing");
			}

			//DatabaseManager.getInstance().saveSession();
			// DatabaseManager.getInstance().tryAddingSomething();
		} catch (Exception ex) {
			ex.printStackTrace();
			throw ex;
		}

		// Hint: Exit here to test database schema only
		//System.exit(0);

		Map<String, HostInfo> hosts = SSLDatabaseManager.getInstance().getAllHosts();
		for(String host : hosts.keySet())
		{
			HostInfo hostInfo = hosts.get(host);
			if(hostInfo != null && hostInfo.getSslProtocol() != null)
			{
				String protocol = hostInfo.getSslProtocol();
				if(protocol != null && protocol != "")
				{
					System.out.println(protocol + ":" + host);					
				}
			}
		}
		
		HttpsChecker checker = new HttpsChecker();

		// blocking operation:
		logger.info("Starting Checker...");
		// controller.start(HttpAnalysisCrawler.class, numberOfCrawlers);
		//checker.start();
		
		while (true) {
			System.err
					.println("Enter: 'abort' to exit process or 'status' for status: ");
			String command = console.readLine();
			if (command.toLowerCase().equals("abort")) {
				break;
			}
			if (command.toLowerCase().equals("status")) {
				try {
					//TODO:
					System.err.println("Not implemented");
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}

		}
		//TODO:
		//controller.shutdown();
		//controller.waitUntilFinish();
		// end of nonblocking version of crawler.

		System.out.println("\n\n-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");
		//TODO: everything saved??
		//System.out.println("Finally storing the results to the database...");
		//SSLDatabaseManager.getInstance().saveSession();
		System.out.println("Done: You can abort this process.");

		// Final output of crawler *IF* it finished:
		System.out.println("\n\n");

		Map<String, HostInfo> visitedHosts = SSLDatabaseManager.getInstance()
				.getCurrentSslSession().getHosts();
		System.out.println("Size of visited hosts: " + visitedHosts.size());
	}
}
