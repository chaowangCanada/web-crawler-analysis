package at.chille.crawler.analysis;

import java.util.Comparator;
import java.util.Map;

public class ComparatorMapStringSslRating implements Comparator<String>{
  Map<String,SslRating> base;
  
  public ComparatorMapStringSslRating(Map<String, SslRating> base) {
      this.base = base;
  }
 
  @Override
  public int compare(String a, String b) {
    if (base.get(a).getValue() >= base.get(b).getValue())
      return 1;
    else
      return -1;
      // returning 0 would merge keys --> TODO: really?
  }
}
