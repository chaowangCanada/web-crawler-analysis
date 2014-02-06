package at.chille.crawler.sslchecker;

import java.util.HashSet;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

public class HttpsDbWorker implements Runnable {
	protected BlockingQueue<HostSslInfo> resultQueue;

	public HttpsDbWorker(BlockingQueue<HostSslInfo> resultQueue) {
		this.resultQueue = resultQueue;
	}

	@Override
	public void run() {
		try {
			
			while (true) {
				if(Thread.interrupted()) {
					System.err.println("DbWorker aborted.");
					return;
				}
				
				HostSslInfo result = resultQueue.take();
				if(result.getHostSslName().length() == 0)
				{
					System.out.println("DbWorker finished.");
					return;
				}
				System.out.println("DbWorker consuming " + result.getHostSslName());
				
				//Now store all ciphersuites in the db before storing the HostSslInfo result object.
				//This is required because HostSslInfo does not specify CascadeType.ALL which would
				//automatically store all ciphersuites. See HostSslInfo for details.
				HashSet<CipherSuite> accepted = new HashSet<CipherSuite>();
				HashSet<CipherSuite> rejected = new HashSet<CipherSuite>();
				HashSet<CipherSuite> failed = new HashSet<CipherSuite>();
				HashSet<CipherSuite> preferred = new HashSet<CipherSuite>();
				
				//
				for(CipherSuite cs : result.getAccepted()) {
					accepted.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
				}
				for(CipherSuite cs : result.getRejected()) {
					accepted.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
				}
				for(CipherSuite cs : result.getFailed()) {
					accepted.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
				}
				for(CipherSuite cs : result.getPreferred()) {
					accepted.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
				}
				
				result.setAccepted(accepted);
				result.setRejected(rejected);
				result.setFailed(failed);
				result.setPreferred(preferred);
				
				SSLDatabaseManager.getInstance().getHostSSLInfoRepository().save(result);
			}

		} catch (Exception e) {
			System.err
					.println("DbWorker caused exception:");
			e.printStackTrace();
		}
	}
}
