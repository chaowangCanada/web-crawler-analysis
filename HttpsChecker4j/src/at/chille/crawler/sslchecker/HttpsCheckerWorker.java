package at.chille.crawler.sslchecker;

import java.io.File;
import java.io.FileInputStream;
import java.util.Date;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.sslchecker.parser.SSLXmlParser;

/**
 * @author chille
 * 
 */
public class HttpsCheckerWorker implements Runnable {
	protected BlockingQueue<String> hostQueue;
	protected BlockingQueue<HostSslInfo> resultQueue;
	protected HttpsCheckerConfig config;

	protected LongCallback successCallback;
	protected LongCallback failureCallback;
	protected LongCallback roundTimeCallback;
	
	public void setSuccessCallback(LongCallback c) {
		this.successCallback = c;
	}
	
	public void setFailureCallback(LongCallback c) {
		this.failureCallback = c;
	}
	
	public void setRoundTimeCallback(LongCallback c) {
		this.roundTimeCallback = c;
	}
	
	public HttpsCheckerWorker(HttpsCheckerConfig config,
			BlockingQueue<String> hostQueue,
			BlockingQueue<HostSslInfo> resultQueue) {
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

		int hostCount = 0;
		Long startTime = (new Date()).getTime();
		
		while (true) {
			try {
				hostCount++;
				String host = hostQueue.take();
				if (host.equalsIgnoreCase("stop")) {
					System.out.println("Worker " + getUniqueId()
							+ " finished.");
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
					if(failureCallback != null)
						failureCallback.Call(0L);
					continue;
				}

				// Now parse the resulting XML file
				FileInputStream stream = new FileInputStream(file);
				SSLXmlParser parser = new SSLXmlParser();
				HostSslInfo sslData = parser.parse(stream);
				sslData.setHostSslName(host);
				sslData.setTimestamp((new Date()).getTime());
				resultQueue.put(sslData);
				
				if(successCallback != null)
					successCallback.Call(0L);
				
				if(roundTimeCallback != null) {
					Long now = (new Date()).getTime();
					roundTimeCallback.Call(now-startTime);
				}
				startTime = (new Date()).getTime();
				
			} catch (Exception e) {
				System.err.println("Worker " + getUniqueId()
						+ " caused exception:");
				e.printStackTrace();
				if(failureCallback != null)
					failureCallback.Call(0L);
			}
		}
	}
}
