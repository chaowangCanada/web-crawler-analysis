package at.chille.sslchecker;

import java.util.ArrayList;

public class ExecConfig {
	private String executable;
	private String requiredVersion;
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
