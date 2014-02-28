package at.chille.crawler.sslchecker;

import java.io.File;
import java.io.FileInputStream;
import java.util.Date;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.sslchecker.parser.SSLXmlParser;

/**
 * worker-class that does actual ssl-scanning
 * @author sammey
 * 
 */
public class HttpsCheckerWorker implements Runnable {
	/**
	 * The queue that contains all hosts to scan.
	 */
	protected BlockingQueue<String> hostQueue;
	/**
	 * The queue that contains scanning-results.
	 */
	protected BlockingQueue<HostSslInfo> resultQueue;
	/**
	 * The configuration
	 */
	protected HttpsCheckerConfig config;

	/**
	 * Callback for successfully scanned hosts
	 */
	protected LongCallback successCallback;
	/**
	 * Callback for scanning-failures
	 */
	protected StringCallback failureCallback;
	/**
	 * Callback for scanning-speed of one successful host
	 */
	protected LongCallback roundTimeCallback;
	
	public void setSuccessCallback(LongCallback c) {
		this.successCallback = c;
	}
	
	public void setFailureCallback(StringCallback c) {
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

	/**
	 * All supported TLS-versions. 
	 * Note: For support of SSLv2 openssl and sslscan need to be compiled appropriately. 
	 * See Readme.txt for details
	 */
	enum TLS_VERSION { TLSv1_2, TLSv1_1, TLSv1_0, SSLv3, SSLv2 };
	
	/**
	 * Scan ssl-hosts. This method takes one host from the queue and scans it according to the configuration.
	 * It calls the callback-methods appropriately, if registered.
	 * This process is repeated until a stop-marker is read. See HttpsCheckerProducer for details.
	 */
	@Override
	public void run() {

		int hostCount = 0;
		String host = "";
		Long startTime = (new Date()).getTime();
		while (true) {
			try {
				startTime = (new Date()).getTime();
				if(Thread.interrupted()) {
					System.err.println("Worker " + getUniqueId()
							+ " aborted.");
					if(failureCallback != null)
						failureCallback.Call("Worker " + getUniqueId()
								+ " aborted.");
					return;
				}
				host = hostQueue.take();
				if (host.equalsIgnoreCase("stop")) {
					System.out.println("Worker " + getUniqueId()
							+ " finished.");
					return;
				}
				System.out.println("Worker " + getUniqueId()
						+ " processing host " + host);
				
				/**
				 * sslData is continuously filled with results from the different TLS-versions.
				 */
				HostSslInfo sslData = new HostSslInfo();
				sslData.setHostSslName(host);
				sslData.setTimestamp(startTime);
				
				if(config.isScanTLSv1_2() && 
						!doScan(host, hostCount++, TLS_VERSION.TLSv1_2, sslData)) {
					if(failureCallback != null)
						failureCallback.Call(host + " " + "TLSv1.2");
					continue;
				}
				
				if(config.isScanTLSv1_1() && 
						!doScan(host, hostCount++, TLS_VERSION.TLSv1_1, sslData)) {
					if(failureCallback != null)
						failureCallback.Call(host + " " + "TLSv1.1");
					continue;
				}
				
				if(config.isScanTLSv1() && 
						!doScan(host, hostCount++, TLS_VERSION.TLSv1_0, sslData)) {
					if(failureCallback != null)
						failureCallback.Call(host + " " + "TLSv1.0");
					continue;
				}
				
				if(config.isScanSSLv3() &&
						!doScan(host, hostCount++, TLS_VERSION.SSLv3, sslData)) {
					if(failureCallback != null)
						failureCallback.Call(host + " " + "SSLv3");
					continue;
				}
				
				if(config.isScanSSLv2() && 
						!doScan(host, hostCount++, TLS_VERSION.SSLv2, sslData)) {
					if(failureCallback != null)
						failureCallback.Call(host + " " + "SSLv2");
					continue;
				}
				
				//Now enqueue the results for HttpsDbWorker
				resultQueue.put(sslData);
				
				if(successCallback != null)
					successCallback.Call(0L);
				
				if(roundTimeCallback != null) {
					Long now = (new Date()).getTime();
					roundTimeCallback.Call(now-startTime);
				}
				
			} catch (Exception e) {
				System.err.println("Worker " + getUniqueId()
						+ " caused exception:");
				e.printStackTrace();
				if(failureCallback != null)
					failureCallback.Call("Worker " + getUniqueId()
							+ " caused exception:" + e.getMessage());
			}
		}
	}
	
	/**
	 * This method does SSL-scanning for one host using ExecConfig and ShellExecutor
	 * The results are parsed using SSLXmlParser.
	 * @param host to scan
	 * @param hostCount of the current thread, is used for generating unique filenames
	 * @param version of TLS
	 * @param result where all scanning-results are appended
	 * @return true on success
	 */
	private boolean doScan(String host, int hostCount, TLS_VERSION version, HostSslInfo result)
	{
		try
		{
		String xmlFileName = config.getTempFolder() + "sslscan_"
				+ getUniqueId() + "_" + String.valueOf(hostCount)
				+ ".xml";

		File file = new File(xmlFileName);
		if (file.exists() && !file.delete()) {
			throw new Exception("Worker " + getUniqueId() + ": unable to delete old file "
					+ file.getCanonicalPath());
		}
		
		ExecConfig sslConfig = new ExecConfig();
		sslConfig.setExecutable("sslscan");
		sslConfig.setParam("--timesleep=" + config.getTimesleep());
		sslConfig.setParam("--xml=" + xmlFileName);
		if (version == TLS_VERSION.TLSv1_2) {
			sslConfig.setParam("--tls1_2");
		} else if (version == TLS_VERSION.TLSv1_1) {
			sslConfig.setParam("--tls1_1");
		} else if (version == TLS_VERSION.TLSv1_0) {
			sslConfig.setParam("--tls1");
		} else if (version == TLS_VERSION.SSLv3) {
			sslConfig.setParam("--ssl3");
		} else if (version == TLS_VERSION.SSLv2) {
			sslConfig.setParam("--ssl2");
		} else {
			throw new Exception("TLS version not supported: " + version.toString());
		}
		sslConfig.setParam(host);
		ShellExecutor checker = new ShellExecutor(sslConfig);
		checker.execute();

		if (!file.exists()) {
			System.err.println("Worker " + getUniqueId()
					+ ": sslscan failed. No file produced.");
			return false;
		}

		// Now parse the resulting XML file
		FileInputStream stream = new FileInputStream(file);
		SSLXmlParser parser = new SSLXmlParser();
		HostSslInfo sslData = parser.parse(stream);
		result.addAccepted(sslData.getAccepted());
		result.addRejected(sslData.getRejected());
		result.addFailed(sslData.getFailed());
		result.addPreferred(sslData.getPreferred());
		return true;
		} catch(Exception e) {
			System.err.println("Worker " + getUniqueId()
					+ " caused exception: " + e.getMessage());
			return false;
		}
	}
}
