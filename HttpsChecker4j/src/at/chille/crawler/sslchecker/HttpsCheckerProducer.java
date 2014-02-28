package at.chille.crawler.sslchecker;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * Class for enqueuing hosts that shall be scanned.
 * @author sammey
 *
 */
public class HttpsCheckerProducer implements Runnable {
	/**
	 * The configuration
	 */
	protected HttpsCheckerConfig config;
	/**
	 * The queue that will be filled with all hosts to scan. See shouldVisitForInspection for details.
	 */
	protected BlockingQueue<String> hostQueue;
	/**
	 * All hosts that need to be filtered by HttpsCheckerProducer
	 */
	protected Map<String, HostInfo> hosts;

	public HttpsCheckerProducer(HttpsCheckerConfig config, BlockingQueue<String> hostQueue, Map<String, HostInfo> hosts) {
		this.config = config;
		this.hostQueue = hostQueue;
		this.hosts = hosts;
	}

	/**
	 * Iterate through all hosts and enqueue all:
	 * - hosts that support SSL
	 * and are not excluded in shouldVisitForInspection
	 */
	@Override
	public void run() {
		try {
			
			for (String host : hosts.keySet()) {
				
				if(Thread.interrupted()) {
					System.err.println("Producer aborted: clearing working queue");
					ClearQueue();
					return;
				}
				//check if host shall be excluded
				if (!shouldVisitForInspection(host))
					System.out.println("Filtering host " + host);
				else {
					HostInfo hostInfo = hosts.get(host);
					//Check if host supports SSL protocol
					if (hostInfo != null && hostInfo.getSslProtocol() != null) {
						String protocol = hostInfo.getSslProtocol();
						if (protocol != null && protocol != "") {
							// System.out.println(protocol + ":" + host);
							System.out
									.println("Producer: enqueuing host " + host);
							//This operation is blocking if the queue is full
							hostQueue.put(host);
						}
					}
				}
			}
			
			//To notify the HttpsCheckerWorkers of finished work, enqueue "stop"-hosts
			enqueueStopMarkers();
			
		} catch (InterruptedException e) {
			System.err.println("Producer aborted: clearing working queue");
			ClearQueue();
			return;
		} catch (Exception e) {
			System.err.println("Producer caused exception:");
			e.printStackTrace();
			ClearQueue();
		}
	}
	
	/**
	 * Enqueue one stop-marker host for each HttpsCheckerWorker in order
	 * to signal them of shutdown
	 * @throws InterruptedException
	 */
	private void enqueueStopMarkers() throws InterruptedException
	{
		for (int i = 0; i < config.getNumWorkers(); i++) {
			hostQueue.put("stop");
		}
	}
	
	/**
	 * Clear all pending hosts from the queue and call enqueueStopMarkers
	 */
	private void ClearQueue()
	{
		// remove pending hosts from queue and signal stop
		hostQueue.clear();
		try {
		enqueueStopMarkers();
		} catch (Exception e) {
		}
	}
	
	/**
	 * Decides if the given Host should be visited for SSL-checking. Returns
	 * true if not on the blacklist and not visited within the last
	 * revisitDelay milliseconds.
	 * 
	 * @param host
	 *            to check
	 * @param revisitDelay
	 *            is the number of milliseconds to wait until host shall be
	 *            visited again. If 0L, host is always visited
	 * @return true if the URL should be visited
	 */
	boolean shouldVisitForInspection(String host) {
		for (String regex : config.getBlacklist()) {
			if (host.matches(regex))
				return false;
		}
		HostSslInfo recentHost = SSLDatabaseManager.getInstance()
				.getMostRecentHostSslInfo(host);
		if (config.getRevisitDelay() > 0L && recentHost != null) {
			if (((recentHost.getTimestamp() + config.getRevisitDelay()) > 
			(new Date()).getTime()))
				return false;
		}
		return true;
	}
}
