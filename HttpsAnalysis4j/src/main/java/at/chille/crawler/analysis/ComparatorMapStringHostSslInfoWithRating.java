package at.chille.crawler.analysis;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;

public class ComparatorMapStringHostSslInfoWithRating implements Comparator<String> {
  Map<String, ArrayList<HostSslInfoWithRating>> base;
  
  public ComparatorMapStringHostSslInfoWithRating(Map<String, ArrayList<HostSslInfoWithRating>> base) {
      this.base = base;
  }
 
  @Override
  public int compare(String a, String b) {
      if (Double.isNaN(base.get(a).get(0).getOverallRating()))
        return 1;
      else if (Double.isNaN(base.get(b).get(0).getOverallRating()) 
               || base.get(a).get(0).getOverallRating() >= base.get(b).get(0).getOverallRating())
        return -1;
      else
        return 1;
      // returning 0 would merge keys --> TODO: really?
  }
}
