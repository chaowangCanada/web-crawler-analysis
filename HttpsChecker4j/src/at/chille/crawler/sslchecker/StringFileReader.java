package at.chille.crawler.sslchecker;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Copied from HttpCrawler4j and slightly adapted. 
 * Now readLines does not catch an exception
 * @original-author chille
 * @author sammey
 *
 */
public class StringFileReader {

	/**
	 * Read all non-comment (starting with #) and non-empty lines from a specified file.
	 * @param filename to read
	 * @return a list of all lines containing data
	 * @throws IOException
	 */
	public static List<String> readLines(String filename) throws IOException {
		BufferedReader reader = null;
		List<String> lines = new ArrayList<String>();
		try {
			reader = new BufferedReader(new InputStreamReader(
					StringFileReader.class.getClassLoader()
							.getResourceAsStream(filename)));
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.length() > 0 && !line.startsWith("#")) {
					lines.add(line);
				}
			}
		} finally {
			try {
				if (reader != null)
					reader.close();
			} catch (IOException e) {
			}
		}
		return lines;
	}
}
