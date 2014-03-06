package at.chille.crawler.analysis;

import java.util.Comparator;

public class ComparatorHostSslInfoWithRating implements Comparator<HostSslInfoWithRating> {

  @Override
  public int compare(HostSslInfoWithRating o1, HostSslInfoWithRating o2) {
    if(o1.getOverallRating() > o2.getOverallRating())
      return -1;
    else if (o1.getOverallRating() < o2.getOverallRating())
      return 1;
    else
      return 0;
  }

}
