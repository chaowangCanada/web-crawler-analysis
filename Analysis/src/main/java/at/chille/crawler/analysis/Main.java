package at.chille.crawler.analysis;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class Main
{
  protected List<Analysis> analysisMethods;
  protected boolean        alwaysTerminate = false;

  protected void showMenu()
  {
    System.out.println("\n");
    int i = 0;
    for (Analysis a : analysisMethods)
    {
      System.out.println(i++ + ". " + a.getName());
    }
    System.out.println("Your Choice: ");
  }

  public Analysis menu()
  {
    int wahl = -1;
    BufferedReader console = new BufferedReader(new InputStreamReader(
        System.in));
    while (wahl < 0)
    {
      try
      {
        showMenu();
        wahl = Integer.parseInt(console.readLine());
      }
      catch (Exception ex)
      {

      }
      if (wahl >= analysisMethods.size())
      {
        wahl = -1;
      }
    }
    return analysisMethods.get(wahl);
  }

  public void run()
  {
    System.out.print("Init Database... ");
    DatabaseManager.getInstance();
    System.out.print("Done.\n");

    System.out.print("Init Analysis... ");
    initAnalysis();
    System.out.print("Done.\n");

    String folder = "./export/";
    new File(folder).mkdirs();

    int error = 0;
    do
    {
      Analysis analysis = menu();
      error = analysis.start();
      String output = analysis.exportToFolder(folder);
      System.out.println("Exported Details: " + output);
    }
    while (error >= 0 && !alwaysTerminate);
  }

  protected void initAnalysis()
  {
    analysisMethods = new ArrayList<Analysis>();
    analysisMethods.add(new AnalysisExit());
    analysisMethods.add(new AnalysisRunAll(false));
    analysisMethods.add(new AnalysisListHosts(false));
    analysisMethods.add(new AnalysisCertIssuers(false));
    analysisMethods.add(new AnalysisCertificateValid(false));
    analysisMethods.add(new AnalysisSSL(false));
    analysisMethods.add(new AnalysisHeader(false));
    analysisMethods.add(new AnalysisCookies(false));

    alwaysTerminate = true; // TODO: set to false
  }

  public static void main(String[] args)
  {
    Main main = new Main();
    main.run();
  }

}
