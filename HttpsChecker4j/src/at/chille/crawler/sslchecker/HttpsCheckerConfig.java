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
	 * This file contains one host per line that shall be scanned. 
	 * If hostFile is empty, the hosts from the database are used.
	 */
	private String hostFile = "";
	
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
	
	/**
	 * The timeout for a host to finish when aborting
	 */
	private Long hostTimeout = 0L;
	
	/**
	 * If true, rejected ciphersuites are not stored in the db.
	 */
	private boolean omitRejectedCipherSuites = false;
	
	/**
	 * If true, failed ciphersuites are not stored in the db.
	 */
	private boolean omitFailedCipherSuites = false;
	
	/**
	 * Specify if given TLS-version shall be scanned
	 */
	private boolean scanTLSv1_2 = true;
	private boolean scanTLSv1_1 = true;
	private boolean scanTLSv1 = true;
	private boolean scanSSLv3 = false;
	private boolean scanSSLv2 = false;
	
	public String toString() {
		String result = "";
		result += "Configuration:";
		if(hostFile != null && hostFile.length() > 0) {
			result += "\n  hosts = " + hostFile;
		} else {
			result += "\n  hosts are read from database";
		}
		result += "\n  numWorkers   = " + numWorkers;
		result += "\n  temp         = " + tempFolder;
		result += "\n  blacklist:";
		for(String s : blacklist) {
			result += "\n    " + s;
		}
		result += "\n  niceWait     = " + timesleep + "ms";
		result += "\n  revisitDelay = " + revisitDelay + "ms";
		result += "\n  hostTimeout  = " + hostTimeout + "ms";
		result += "\n  TLSv1.2      = " + scanTLSv1_2;
		result += "\n  TLSv1.1      = " + scanTLSv1_1;
		result += "\n  TLSv1.0      = " + scanTLSv1;
		result += "\n  SSLv3        = " + scanSSLv3;
		result += "\n  SSLv2        = " + scanSSLv2;
		result += "\n  omitRejected = " + omitRejectedCipherSuites;
		result += "\n  omitFailed   = " + omitFailedCipherSuites;
		result += "\n";
		
		return result;
	}
	
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

	public String getHostFile() {
		return hostFile;
	}
	
	public void setHostFile(String hostFile) {
		this.hostFile = hostFile;
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

	public Long getHostTimeout() {
		return hostTimeout;
	}
	public void setHostTimeout(Long hostTimeout) {
		this.hostTimeout = hostTimeout;
	}
	public boolean omitRejectedCipherSuites() {
		return omitRejectedCipherSuites;
	}

	public void setOmitRejectedCipherSuites(boolean omitRejectedCipherSuites) {
		this.omitRejectedCipherSuites = omitRejectedCipherSuites;
	}

	public boolean omitFailedCipherSuites() {
		return omitFailedCipherSuites;
	}

	public void setOmitFailedCipherSuites(boolean omitFailedCipherSuites) {
		this.omitFailedCipherSuites = omitFailedCipherSuites;
	}

	public boolean isScanTLSv1_2() {
		return scanTLSv1_2;
	}
	
	public void setScanTLSv1_2(boolean scanTLSv1_2) {
		this.scanTLSv1_2 = scanTLSv1_2;
	}
	
	public boolean isScanTLSv1_1() {
		return scanTLSv1_1;
	}
	
	public void setScanTLSv1_1(boolean scanTLSv1_1) {
		this.scanTLSv1_1 = scanTLSv1_1;
	}
	
	public boolean isScanTLSv1() {
		return scanTLSv1;
	}

	public void setScanTLSv1(boolean scanTLSv1) {
		this.scanTLSv1 = scanTLSv1;
	}

	public boolean isScanSSLv3() {
		return scanSSLv3;
	}

	public void setScanSSLv3(boolean scanSSLv3) {
		this.scanSSLv3 = scanSSLv3;
	}

	public boolean isScanSSLv2() {
		return scanSSLv2;
	}

	public void setScanSSLv2(boolean scanSSLv2) {
		this.scanSSLv2 = scanSSLv2;
	}

	public Iterable<String> getBlacklist()
	{
		return blacklist;
	}
	
	public void addBlacklist(String entry)
	{
		blacklist.add(entry);
	}
	
	/**
	 * Currently not used.
	 * @param filename to store xml-results
	 * @param host to scan
	 * @return a ShellExecutor instance for ssl-scanning
	 */
	public ShellExecutor getSslChecker(String filename, String host)
	{
		ExecConfig config = new ExecConfig();
		config.setExecutable("sslscan");
		config.setParam("--timesleep=" + timesleep);
		config.setParam("--xml=" + filename);
		config.setParam(host);
		return new ShellExecutor(config);
	}
	
	/**
	 * Check if the correct version of sslscan is installed.
	 * It must be self-compiled to support --timesleep option.
	 * @return true on success
	 */
	public boolean testSslChecker()
	{
		ExecConfig config = new ExecConfig();
		config.setExecutable("sslscan");
		config.setRequiredVersion("1.8.2_t");
		ShellExecutor exec = new ShellExecutor(config);
		return exec.TestConfig();
	}
}
