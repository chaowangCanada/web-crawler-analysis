package at.chille.crawler.sslchecker;

import java.util.HashMap;
import java.util.Map;

import javax.inject.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.crawler.database.model.*;
import at.chille.crawler.database.model.sslchecker.*;
import at.chille.crawler.database.repository.*;
import at.chille.crawler.database.repository.sslchecker.*;

/**
 * Database Manager for HttpsChecker4j
 * 
 * @author chille
 * 
 */
@Component
public class SSLDatabaseManager {
	private static ClassPathXmlApplicationContext context = null;
	private static SSLDatabaseManager _instance;
	protected CrawlingSession currentCrawlingSession;

	/**
	 * Singleton accessor
	 * @return the only SSLDatabaseManager instance
	 */
	public static SSLDatabaseManager getInstance() {
		if (_instance == null) {
			_instance = SSLDatabaseManager.getContext().getBean(
					SSLDatabaseManager.class);
		}
		return _instance;
	}

	/**
	 * Load the last crawling session from the db. 
	 * The result is stored in currentCrawlingSession
	 */
	public void loadLastCrawlingSession() {
		long timeStartedMax = 0;
		for (CrawlingSession cs : crawlingSessionRepository.findAll()) {
			if (cs.getTimeStarted().longValue() > timeStartedMax) {
				timeStartedMax = cs.getTimeStarted().longValue();
				this.currentCrawlingSession = cs;
			}
		}
	}

	protected Map<String, HostSslInfo> lastHostSslInfos;
	public synchronized void loadLastHostSslInfos()
	{
		lastHostSslInfos = new HashMap<String, HostSslInfo>();
		Iterable<HostSslInfo> hosts = hostSslInfoRepository.findAll();
		for (HostSslInfo h : hosts) {
			HostSslInfo lastInfo = lastHostSslInfos.get(h.getHostSslName());
			if(lastInfo == null) {
				lastHostSslInfos.put(h.getHostSslName(), h);
			} else {
				Long lastTimestamp = lastInfo.getTimestamp() == null ? 
						0L : lastInfo.getTimestamp();
				Long currentTimestamp = h.getTimestamp() == null ? 
						0L : h.getTimestamp();
				
				if (currentTimestamp > lastTimestamp) {
					//found a newer HostSslInfo
					lastHostSslInfos.put(h.getHostSslName(), h);
				}
			}
		}
	}
	
	public synchronized HostSslInfo getMostRecentHostSslInfo(String host) {
		return lastHostSslInfos.get(host);
	}
	
	/**
	 * @deprecated
	 * Return the most recent HostSslInfo object from the db  
	 * @param host    String of the requested host
	 * @return the most recent HostSslInfo object or null;
	 */
	public synchronized HostSslInfo getMostRecentHostSslInfoDb(String host) {
		HostSslInfo foundHostInfo = null;
		Long foundTimestamp = 0L;
		Iterable<HostSslInfo> hosts = hostSslInfoRepository.findAll();
		for (HostSslInfo h : hosts) {
			if (h.getHostSslName().equalsIgnoreCase((host))) {
				Long currentTimestamp = h.getTimestamp() == null ? 0L : h
						.getTimestamp();
				if (foundHostInfo == null
						|| (currentTimestamp > foundTimestamp)) {
					foundHostInfo = h;
					foundTimestamp = foundHostInfo.getTimestamp() == null ? 0L
							: foundHostInfo.getTimestamp();
				}
			}
		}
		return foundHostInfo;
	}

	/**
	 * Store one CipherSuite in the database. If it already exists in the db, 
	 * the CipherSuite object from the db is returned. 
	 * 
	 * @param cs is the CipherSuite to store
	 * @return the CipherSuite object from the db or null on error
	 */
	public synchronized CipherSuite saveCipherSuite(CipherSuite cs) {
		try {
			return cipherSuiteRepository.save(cs);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Retrieves all HostInfo objects from the last crawling session.
	 * @return a map of all HostInfo objects
	 */
	public Map<String, HostInfo> getAllHosts() {
		return currentCrawlingSession.getHosts();
	}

	/**
	 * Initialize the ApplicationContext for the springframework. 
	 * The specified xml-file contains the packages that are scanned
	 * by the springframework for @Entity classes.
	 * @return the ApplicationContext
	 */
	protected static synchronized ApplicationContext getContext() {
		if (context == null) {
			context = new ClassPathXmlApplicationContext();
			String[] locations = { "classpath*:resthubContext.xml",
					"classpath*:application-context-democlient.xml", };
			context.getEnvironment().setActiveProfiles("resthub-jpa");
			context.setConfigLocations(locations);
			context.refresh();
		}

		return context;
	}

	@Autowired
	private CrawlingSessionRepository crawlingSessionRepository;
	@Autowired
	private HostSslInfoRepository     hostSslInfoRepository;
	@Autowired
	private CipherSuiteRepository     cipherSuiteRepository;

	public HostSslInfoRepository getHostSSLInfoRepository() {
		return hostSslInfoRepository;
	}

	public CipherSuiteRepository getCipherSuiteRepository() {
		return cipherSuiteRepository;
	}

	@Inject
	@Named("crawlingSessionRepository")
	public void setCrawlingSessionRepository(CrawlingSessionRepository t) {
		this.crawlingSessionRepository = t;
	}

	@Inject
	@Named("hostSslInfoRepository")
	public void setHostSslInfoRepository(HostSslInfoRepository t) {
		this.hostSslInfoRepository = t;
	}

	@Inject
	@Named("cipherSuiteRepository")
	public void setCipherSuiteRepository(CipherSuiteRepository t) {
		this.cipherSuiteRepository = t;
	}
}
