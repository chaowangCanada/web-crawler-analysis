package at.chille.crawler.sslchecker;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.model.sslchecker.CipherSuite;
import at.chille.crawler.database.model.sslchecker.HostSslInfo;
import at.chille.crawler.sslchecker.parser.SSLXmlParser;
import at.chille.crawler.sslchecker.parser.SslInfo;

public class HttpsDbWorker implements Runnable {
	protected BlockingQueue<SslInfo> resultQueue;

	public HttpsDbWorker(BlockingQueue<SslInfo> resultQueue) {
		this.resultQueue = resultQueue;
	}

	@Override
	public void run() {
		try {
			
			while (true) {
				SslInfo result = resultQueue.take();
				if(result.getHost().length() == 0)
				{
					System.out.println("DbWorker now stopping");
					return;
				}
				System.out.println("DbWorker consuming " + result.getHost());
				
				HostSslInfo hostSslInfo = new HostSslInfo();
				hostSslInfo.setCipherSuites(result.getAccepted());
				hostSslInfo.setPreferredCipherSuites(result.getPreferred());
				//hostSslInfo.setSslSession(SSLDatabaseManager.getInstance().getCurrentSslSession());
				SSLDatabaseManager.getInstance().hostSslInfoRepository.save(hostSslInfo);
			}

		} catch (Exception e) {
			System.err
					.println("DbWorker caused exception:");
			e.printStackTrace();
		}
	}
}
