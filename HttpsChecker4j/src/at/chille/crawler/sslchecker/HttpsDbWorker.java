package at.chille.crawler.sslchecker;

import java.util.HashSet;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;

/**
 * worker-class for storing scan-results in the database
 * @author sammey
 *
 */
public class HttpsDbWorker implements Runnable {
	/**
	 * The queue containing scan-results that shall be stored in the database
	 */
	protected BlockingQueue<HostSslInfo> resultQueue;
	/**
	 * The configuration
	 */
	protected HttpsCheckerConfig config;
	
	public HttpsDbWorker(HttpsCheckerConfig config,
			BlockingQueue<HostSslInfo> resultQueue) {
		this.config = config;
		this.resultQueue = resultQueue;
	}

	/**
	 * This method takes one result from the resultQueue and stores it in the database.
	 * Ciphersuites from one result are merged with the ciphersuites that are already
	 * in the database. This is done via saveCipherSuite. 
	 * This process is repeated until an empty HostSslInfo object is read from the queue. 
	 * See HttpsCheckerController.
	 */
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
				
				/**
				 * Now store all ciphersuites in the db before storing the HostSslInfo result object.
				 *
				 * This is required because HostSslInfo does not specify CascadeType.ALL which would
				 * automatically store all ciphersuites. See HostSslInfo for details.
				 * saveCipherSuite merges the ciphersuite from the scan-result with those
				 * already existing in the database.
				 */
				HashSet<CipherSuite> accepted = new HashSet<CipherSuite>();
				HashSet<CipherSuite> rejected = new HashSet<CipherSuite>();
				HashSet<CipherSuite> failed = new HashSet<CipherSuite>();
				HashSet<CipherSuite> preferred = new HashSet<CipherSuite>();
				
				for(CipherSuite cs : result.getAccepted()) {
					accepted.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
				}
				if(!config.omitRejectedCipherSuites()) {
					for(CipherSuite cs : result.getRejected()) {
						rejected.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
					}
				}
				if(!config.omitFailedCipherSuites()) {
					for(CipherSuite cs : result.getFailed()) {
						failed.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
					}
				}
				for(CipherSuite cs : result.getPreferred()) {
					preferred.add(SSLDatabaseManager.getInstance().saveCipherSuite(cs));					
				}
				
				result.setAccepted(accepted);
				result.setRejected(rejected);
				result.setFailed(failed);
				result.setPreferred(preferred);
				
				//Now store the HostSslInfo into the db
				SSLDatabaseManager.getInstance().getHostSSLInfoRepository().save(result);
			}

		} catch (Exception e) {
			System.err
					.println("DbWorker caused exception:");
			e.printStackTrace();
		}
	}
}
