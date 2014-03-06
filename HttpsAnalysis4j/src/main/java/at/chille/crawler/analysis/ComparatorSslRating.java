package at.chille.crawler.analysis;

import java.util.Comparator;

public class ComparatorSslRating implements Comparator<SslRating> {

  @Override
  public int compare(SslRating o1, SslRating o2) {
    if (o1.getValue() > o2.getValue())
      return -1;
    else if (o1.getValue() < o2.getValue())
      return 1;
    else
      return 0;
  }
}
