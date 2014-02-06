package at.chille.crawler.sslchecker;

import java.util.ArrayList;

/**
 * Class ExecConfig contains configuration parameters for 
 * one shell execution command.
 * 
 * @author sammey
 *
 */
public class ExecConfig {
	/**
	 * The executable string
	 */
	private String executable;
	
	/**
	 * The expected version string that is returned by the
	 * executable when passing --version
	 */
	private String requiredVersion;
	
	/**
	 * A list of parameters
	 */
	private ArrayList<String> params;
	
	public ExecConfig()
	{
		params = new ArrayList<String>();
	}
	
	public String getExecutable() {
		return executable;
	}
	
	public void setExecutable(String executable) {
		this.executable = executable;
	}
	
	public String getRequiredVersion() {
		return requiredVersion;
	}
	
	public void setRequiredVersion(String requiredVersion) {
		this.requiredVersion = requiredVersion;
	}
	
	public ArrayList<String> getParams() {
		return params;
	}
	
	public void setParams(ArrayList<String> params) {
		this.params = params;
	}
	
	public void setParam(String param) {
		this.params.add(param);
	}
}
