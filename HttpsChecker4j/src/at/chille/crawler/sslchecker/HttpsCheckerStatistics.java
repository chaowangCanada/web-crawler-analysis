package at.chille.crawler.sslchecker;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;

import javax.security.auth.callback.TextOutputCallback;

public class HttpsCheckerStatistics {
	private int successes;
	private int failures;
	private ArrayList<Long> speed;
	private Long startTime;
	private String logfilename = "failures.txt";
	private OutputStream logfileStream;
	public HttpsCheckerStatistics() throws IOException
	{
		successes = 0;
		failures = 0;
		speed = new ArrayList<Long>();
		startTime = (new Date()).getTime();
		logfileStream = new FileOutputStream(logfilename, true);
		String separator = "================================================================================\n";
		String header = "Log started: " + (new Date()).toString();
		logfileStream.write(separator.getBytes());
		logfileStream.write(header.getBytes());
	}
	
	@Override
	protected void finalize() throws Throwable {
		logfileStream.close();
		super.finalize();
	}
	
	public synchronized void incrementSuccesses()
	{
		successes++;
	}
	
	public synchronized void incrementFailures()
	{
		failures++;
	}
	
	public synchronized void addPageScanSpeed(Long speed)
	{
		this.speed.add(speed);
	}
	
	public synchronized int getSuccesses()
	{
		return successes;
	}
	
	public synchronized int getFailures()
	{
		return failures;
	}
	
	/**
	 * @return the average page scan speed in seconds
	 */
	public synchronized float getAveragePageScanSpeed()
	{
		float sum = 0;
		int count = this.speed.size();
		for(Long speed : this.speed) {
			sum += speed / (float)count;
		}
		return sum / 1000.0f;
	}
	
	/**
	 * @return the slowest scan speed in seconds
	 */
	public synchronized float getSlowestScanSpeed()
	{
		Long slow = 0L;
		for(Long speed : this.speed) {
			if(speed > slow) {
				slow = speed;
			}
		}
		return slow / 1000.0f;
	}
	
	/**
	 * @return the fastest scan speed in seconds
	 */
	public synchronized float getFastestPageScanSpeed()
	{
		Long fast = Long.MAX_VALUE;
		for(Long speed : this.speed) {
			if(speed < fast) {
				fast = speed;
			}
		}
		return fast / 1000.0f;
	}
	
	/**
	 * @return the pages per minute
	 */
	public synchronized float getPagesPerMinute()
	{
		Long upTime = (new Date()).getTime() - startTime;
		float minutes = upTime / (60*1000.0f);
		return this.speed.size() / minutes;
	}

	public void logFailure(String value) {
		try {
			value = value.trim() + "\n";
			logfileStream.write(value.getBytes());
		} catch (IOException e) {
		}
	}
}
