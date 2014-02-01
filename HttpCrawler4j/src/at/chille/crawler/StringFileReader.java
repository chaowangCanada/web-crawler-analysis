package at.chille.crawler;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class StringFileReader {

	public static List<String> readLines(String filename) {
		BufferedReader reader = null;
		List<String> lines = new ArrayList<String>();
		try {
			// reader = new BufferedReader(new FileReader(filename));
			reader = new BufferedReader(new InputStreamReader(
					StringFileReader.class.getClassLoader()
							.getResourceAsStream(filename)));
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.length() > 0 && !line.startsWith("#")) {
					lines.add(line);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (reader != null)
					reader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return lines;
	}

}
