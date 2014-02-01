package at.chille.crawler.sslchecker;

import java.util.HashSet;

public class HttpsCheckerConfig {
	private String tempFolder;
	private HashSet<String> blacklist;
	private int timesleep;
	
	public HttpsCheckerConfig(String tempFolder, int timesleep)
	{
		this.setTempFolder(tempFolder);
		this.setTimesleep(timesleep);
		blacklist = new HashSet<String>();
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
