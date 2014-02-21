package at.chille.crawler.sslchecker;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Class ShellExecutor executes a shell command that was configured
 * via ExecConfig. 
 * 
 * @author sammey
 *
 */
public class ShellExecutor {

	private ExecConfig config = null;
	
	public ShellExecutor(ExecConfig config)
	{
		this.config = config;
	}
	
	/**
	 * @return a String ready for execution. It contains the executable and all parameters separated with spaces
	 */
	private String composeExecString()
	{
		String exec = config.getExecutable();
		for(String p : config.getParams())
			exec += " " + p;
		return exec;
	}
	
	/**
	 * @return an executable String for checking the version number of the executable
	 */
	private String composeVersionExecString()
	{
		String exec = config.getExecutable();
		exec += " --version";
		return exec;
	}
	
	/**
	 * Execute the shell command
	 * @param command to be executed
	 * @return the output of the executed command.
	 */
	private String runProgram(String command)
	{
		try {
			Process p = Runtime.getRuntime().exec(command);
			String result = "";
			//TODO: Use wait-timeout and retry
			p.waitFor();
			if(Thread.interrupted()) {
				System.err.println("Aborting ShellExecutor command " + command);
				p.destroy();
			}
			
			BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while(reader.ready())
			{
				String line = reader.readLine();
				result += line + "\r\n";
			}
			return result;

		} catch (Exception e) {
			return "";
		}
	}
	
	/**
	 * Checks if the shell command is executable and responds
	 * with the expected version string
	 * @return true on success
	 */
	public boolean TestConfig()
	{
		String result = runProgram(composeVersionExecString());
		if(result.contains(config.getRequiredVersion()))
			return true;
		else
			return false;
	}
	
	/**
	 * Execute the shell command
	 * @return the output of the command
	 */
	public String execute()
	{
		return runProgram(composeExecString());
	}
}
