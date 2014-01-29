package at.chille.crawler.sslchecker;

import java.io.File;
import java.io.FileInputStream;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.sslchecker.parser.SSLXmlParser;
import at.chille.crawler.sslchecker.parser.SslInfo;

/**
 * @author chille
 * 
 */
public class HttpsCheckerWorker implements Runnable {
	protected BlockingQueue<String> hostQueue;
	protected BlockingQueue<SslInfo> resultQueue;
	protected HttpsCheckerConfig config;

	public HttpsCheckerWorker(HttpsCheckerConfig config,
			BlockingQueue<String> hostQueue,
			BlockingQueue<SslInfo> resultQueue) {
		this.config = config;
		this.hostQueue = hostQueue;
		this.resultQueue = resultQueue;
	}

	public String getUniqueId() {
		return String.valueOf(Thread.currentThread().getId());
	}

	public boolean visit(HostInfo hostInfo) {
		System.out.println("SSL-checking host " + hostInfo.getHostName());
		return false;
	}

	@Override
	public void run() {
		try {
			int hostCount = 0;
			while (true) {
				hostCount++;
				String host = hostQueue.take();
				if (host.equalsIgnoreCase("stop")) {
					System.out.println("Worker " + getUniqueId()
							+ " now stopping");
					return;
				}
				System.out.println("Worker " + getUniqueId()
						+ " processing host " + host);
				String xmlFileName = config.getTempFolder() + "sslscan_"
						+ getUniqueId() + "_" + String.valueOf(hostCount)
						+ ".xml";

				File file = new File(xmlFileName);
				if (file.exists() && !file.delete()) {
					System.err.println("Unable to delete old file "
							+ file.getCanonicalPath());
					return;
				}

				ExecConfig sslConfig = new ExecConfig();
				sslConfig.setExecutable("sslscan");
				sslConfig.setParam("--timesleep=" + config.getTimesleep());
				sslConfig.setParam("--xml=" + xmlFileName);
				sslConfig.setParam(host);
				ShellExecutor checker = new ShellExecutor(sslConfig);
				checker.execute();

				if (!file.exists()) {
					System.err.println("Worker " + getUniqueId()
							+ ": sslscan failed. No file produced.");
					continue;
				}

				// Now parse the resulting XML file
				FileInputStream stream = new FileInputStream(file);
				SSLXmlParser parser = new SSLXmlParser();
				SslInfo sslData = parser.parse(stream);
				sslData.setHost(host);
				resultQueue.add(sslData);
			}

		} catch (Exception e) {
			System.err
					.println("Worker " + getUniqueId() + " caused exception:");
			e.printStackTrace();
		}
	}
}
