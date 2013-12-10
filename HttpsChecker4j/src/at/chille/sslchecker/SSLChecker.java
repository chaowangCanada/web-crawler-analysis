package at.chille.sslchecker;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class SSLChecker {

	private ExecConfig config = null;
	public SSLChecker(ExecConfig config)
	{
		this.config = config;
	}
	
	private String composeExecString()
	{
		String exec = config.getExecutable();
		for(String p : config.getParams())
			exec += " " + p;
		return exec;
	}
	
	private String composeVersionExecString()
	{
		String exec = config.getExecutable();
		exec += " --version";
		return exec;
	}
	
	private String runProgram(String command)
	{
		try {
			Process p = Runtime.getRuntime().exec(command);
			String result = "";
			p.waitFor();
			
			BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while(reader.ready())
			{
				result += reader.readLine() + "\r\n";
			}
			return result;

		} catch (Exception e) {
			return "";
		}
	}
	
	public boolean TestConfig()
	{
		String result = runProgram(composeVersionExecString());
		if(result.contains(config.getRequiredVersion()))
			return true;
		else
			return false;
	}
	
	public String execute()
	{
		return runProgram(composeExecString());
	}
}
