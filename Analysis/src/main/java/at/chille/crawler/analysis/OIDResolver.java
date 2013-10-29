package at.chille.crawler.analysis;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves Known OIDs in Certificates to the defined name. Needs a Config file with a specific
 * format (see loadTxtFile)
 * 
 * @author chille
 * 
 */
public class OIDResolver
{
  public Map<String, String> oidMapping;

  public OIDResolver()
  {
    oidMapping = new HashMap<String, String>();
  }

  /**
   * Loads the configuration for the OID-String-Mapping from an txt-file, where the OID and the Name
   * is separated by the first whitespace.
   * 
   * @param filename
   */
  public void loadTxtFile(String filename)
  {
    List<String> lines = StringFileReader.readLines(filename);
    for (String line : lines)
    {
      int pos = line.indexOf(' ');
      String oid = line.substring(0, pos);
      String description = line.substring(pos + 1);
      oidMapping.put(oid, description);
    }
  }

  /**
   * Resolves an OID to the given Name
   * 
   * @param oid
   * @return
   */
  public String resolve(String oid)
  {
    return oidMapping.get(oid);
  }
}
