package at.chille.crawler.sslchecker;

import java.util.HashSet;

/**
 * Class HttpsCheckerConfig contains configuration parameters for all HttpsWorkers
 * 
 * @author sammey
 *
 */
public class HttpsCheckerConfig {
	/**
	 * The number of HttpsCheckerWorker threads that do ssl-scanning. 
	 * Note: There is always exactly one HttpsDbWorker for DB-access. 
	 */
	private int numWorkers = 1;
	
	/**
	 * The temporary folder to store intermediate results
	 */
	private String tempFolder;
	/**
	 * The regex blacklist of hosts which should be skipped
	 */
	private HashSet<String> blacklist;
	/**
	 * The time-delay to wait between two TLS ClientHello messages
	 */
	private int timesleep = 0;
	/**
	 * The time-delay after which another scan to the same host is allowed
	 */
	private Long revisitDelay = 0L;
	
	public HttpsCheckerConfig(int numWorkers, String tempFolder, int timesleep)
	{
		this.setNumWorkers(numWorkers);
		this.setTempFolder(tempFolder);
		this.setTimesleep(timesleep);
		this.blacklist = new HashSet<String>();
	}

	public int getNumWorkers() {
		return numWorkers;
	}

	public void setNumWorkers(int numWorkers) {
		this.numWorkers = numWorkers;
	}

	public String getTempFolder() {
		return tempFolder;
	}

	public void setTempFolder(String tempFolder) {
		if(!tempFolder.endsWith("/"))
			tempFolder = tempFolder + "/";
		this.tempFolder = tempFolder;
	}

	public int getTimesleep() {
		return timesleep;
	}

	public void setTimesleep(int timesleep) {
		this.timesleep = timesleep;
	}
	
	public Long getRevisitDelay() {
		return revisitDelay;
	}

	public void setRevisitDelay(Long revisitDelay) {
		this.revisitDelay = revisitDelay;
	}

	public Iterable<String> getBlacklist()
	{
		return blacklist;
	}
	
	public void addBlacklist(String entry)
	{
		blacklist.add(entry);
	}
	
	public ShellExecutor getSslChecker(String filename, String host)
	{
		ExecConfig config = new ExecConfig();
		config.setExecutable("sslscan");
		config.setParam("--timesleep=" + timesleep);
		config.setParam("--xml=" + filename);
		config.setParam(host);
		return new ShellExecutor(config);
	}
	
	public boolean testSslChecker()
	{
		ExecConfig config = new ExecConfig();
		config.setExecutable("sslscan");
		config.setRequiredVersion("1.8.2_t");
		ShellExecutor exec = new ShellExecutor(config);
		return exec.TestConfig();
	}
}
