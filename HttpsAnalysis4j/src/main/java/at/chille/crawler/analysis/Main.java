package at.chille.crawler.analysis;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class Main
{
  protected List<SslAnalysis> analysisMethods;
  protected boolean        alwaysTerminate = false;

  protected void showMenu()
  {
    System.out.println("\n");
    int i = 0;
    for (SslAnalysis a : analysisMethods)
    {
      System.out.println(i++ + ". " + a.getName());
    }
    System.out.println("Your Choice: ");
  }

  public SslAnalysis menu()
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
      SslAnalysis analysis = menu();
      error = analysis.start();
      String output = analysis.exportToFolder(folder);
      System.out.println("Exported Details: " + output);
    }
    while (error >= 0 && !alwaysTerminate);
  }

  protected void initAnalysis()
  {
    analysisMethods = new ArrayList<SslAnalysis>();
    analysisMethods.add(new SslAnalysisExit());
    analysisMethods.add(new SslAnalysis(false));
    analysisMethods.add(new SslAnalysis(true));

    alwaysTerminate = true; // TODO: set to false
  }

  public static void main(String[] args)
  {
    Main main = new Main();
    main.run();
  }

}
