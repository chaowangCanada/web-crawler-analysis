package at.chille.crawler.sslchecker;

import java.util.HashSet;
import java.util.concurrent.BlockingQueue;

import org.h2.engine.Session;

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
				HostSslInfo result = resultQueue.take();
				if(result.getHostSslName().length() == 0)
				{
					System.out.println("DbWorker now stopping");
					return;
				}
				System.out.println("DbWorker consuming " + result.getHostSslName());
				
				//SSLDatabaseManager.getInstance().cipherSuiteRepository.
//				Iterable<CipherSuite> iter = SSLDatabaseManager.getInstance().cipherSuiteRepository.findAll();
//				HashSet<CipherSuite> ciphers = new HashSet<CipherSuite>();
//				while(iter.iterator().hasNext())
//				ciphers.add(iter.iterator().next());
//				
//				for(CipherSuite c : ciphers)
//				{
//					if(result.getAccepted().contains(c)){
//						result.getAccepted().remove(c);
//						result.getAccepted().add(c);
//				}
//				
//				for(CipherSuite c : result.getRejected())
//				{
//					if(ciphers.contains(c))
//						result.getRejected().remove(c);
//				}
//				
//				for(CipherSuite c : result.getAccepted())
//				{
//					if(ciphers.contains(c))
//						result.getAccepted().remove(c);
//				}
//				
//				for(CipherSuite c : result.getAccepted())
//				{
//					if(ciphers.contains(c))
//						result.getAccepted().remove(c);
//				}
				
				//hostSslInfo.setSslSession(SSLDatabaseManager.getInstance().getCurrentSslSession());
				SSLDatabaseManager.getInstance().hostSslInfoRepository.save(result);
			}

		} catch (Exception e) {
			System.err
					.println("DbWorker caused exception:");
			e.printStackTrace();
		}
	}
}
