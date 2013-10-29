package at.chille.crawler.analysis;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * implements the PHP-Function readLines. Given a filename, the file is loaded from the Ressources
 * and splitted by newlines.
 * 
 * @author chille
 * 
 */
public class StringFileReader
{

  /**
   * implements the PHP-Function readLines. Given a filename, the file is loaded from the Ressources
   * and splitted by newlines. Returns an empty list if an Exception occurs. (Error is printed to
   * System.err)
   * 
   * @param filename
   * @return newline-splitted Strings in the given file
   */
  public static List<String> readLines(String filename)
  {
    BufferedReader reader = null;
    List<String> lines = new ArrayList<String>();
    try
    {
      // reader = new BufferedReader(new FileReader(filename));
      reader = new BufferedReader(new InputStreamReader(
          StringFileReader.class.getClassLoader()
              .getResourceAsStream(filename)));
      String line;
      while ((line = reader.readLine()) != null)
      {
        if (line.length() > 0 && !line.startsWith("#"))
        {
          lines.add(line);
        }
      }
    }
    catch (Exception e)
    {
      System.err.println("Probably file not found: " + filename);
      e.printStackTrace();
    }
    finally
    {
      try
      {
        if (reader != null)
          reader.close();
      }
      catch (IOException e)
      {
        e.printStackTrace();
      }
    }

    return lines;
  }

}
