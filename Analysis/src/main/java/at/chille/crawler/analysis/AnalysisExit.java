package at.chille.crawler.analysis;

/**
 * Empty Analysis to implement the Exit-Menu Entry in the dynamic Menu.
 * 
 * @author chille
 * 
 */
public class AnalysisExit extends Analysis
{

  public AnalysisExit()
  {
    super();
  }

  @Override
  public void init()
  {
    this.name = "Exit";
    this.description = "Close Analysis Program";
  }

  @Override
  public int analyze()
  {
    out.println("Bye.");
    return -1;
  }

}
