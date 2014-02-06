package at.chille.crawler.analysis;

/**
 * Empty Analysis to implement the Exit-Menu Entry in the dynamic Menu.
 * 
 * @author chille
 * 
 */
public class SslAnalysisExit extends SslAnalysis
{

  public SslAnalysisExit()
  {
    super(false);
    name = "Exit";
  }

  public int analyze()
  {
    description = "Close Analysis Program";
    out.println("Bye.");
    return -1;
  }

}
