package at.chille.crawler.sslchecker;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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
	protected StringCallback failureCallback;
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

	public boolean visit(HostInfo hostInfo) {
		System.out.println("SSL-checking host " + hostInfo.getHostName());
		return false;
	}

	enum TLS_VERSION { TLSv2, TLSv1, SSLv3, SSLv2 };
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
				
				HostSslInfo sslData = new HostSslInfo();
				sslData.setHostSslName(host);
				sslData.setTimestamp(startTime);
				
				if(config.isScanTLSv1() && 
						!doScan(host, hostCount++, TLS_VERSION.TLSv1, sslData)) {
					if(failureCallback != null)
						failureCallback.Call(host + " " + "TLSv1");
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
		if (version == TLS_VERSION.TLSv1) {
			//do nothing
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
