package at.chille.crawler.sslchecker;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

public class HttpsCheckerProducer implements Runnable {
	protected HttpsCheckerConfig config;
	protected BlockingQueue<String> hostQueue;
	protected Map<String, HostInfo> hosts;

	public HttpsCheckerProducer(HttpsCheckerConfig config, BlockingQueue<String> hostQueue, Map<String, HostInfo> hosts) {
		this.config = config;
		this.hostQueue = hostQueue;
		this.hosts = hosts;
	}

	@Override
	public void run() {
		try {
			
			for (String host : hosts.keySet()) {
				
				if(Thread.interrupted()) {
					System.err.println("Producer aborted: clearing working queue");
					ClearQueue();
					return;
				}
				if (!shouldVisitForInspection(host))
					System.out.println("Filtering host " + host);
				else {
					HostInfo hostInfo = hosts.get(host);
					if (hostInfo != null && hostInfo.getSslProtocol() != null) {
						String protocol = hostInfo.getSslProtocol();
						if (protocol != null && protocol != "") {
							// System.out.println(protocol + ":" + host);
							System.out
									.println("Producer: enqueuing host " + host);
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
	
	private void enqueueStopMarkers() throws InterruptedException
	{
		for (int i = 0; i < config.getNumWorkers(); i++) {
			hostQueue.put("stop");
		}
	}
	
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
	 * true if is not on the blacklist and it was not visited within the last
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
