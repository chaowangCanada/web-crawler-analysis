package at.chille.crawler.analysis;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class Main
{
  private List<String> analysisOptions;
  private boolean alwaysTerminate = false;
  private SslAnalysis sa;

  private void showMenu()
  {
    System.out.println("\n");
    int i = 0;
    for (String s : analysisOptions)
    {
      System.out.println(i++ + ". " + s);
    }
    System.out.println("Your Choice: ");
  }

  private int menu()
  {
    int wahl = -1;
    BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
    
    while (wahl < 0)
    {
      try {
        showMenu();
        wahl = Integer.parseInt(console.readLine());
      } catch (Exception ex) {
        System.err.println(ex.getMessage());
      }
      
      if (wahl >= analysisOptions.size() || wahl < 0) {
        wahl = -1;
        System.out.println("Info: Options are only available between 0 and " + (analysisOptions.size()-1));
      }
    }
    return wahl;
  }

  private void run()
  {
    System.out.print("Init Database... ");
    DatabaseManager.getInstance();
    System.out.print("Done.\n");

    System.out.print("Init Analysis... ");
    initAnalysis();
    System.out.print("Done.\n");

    int error = 0;
    do
    {
      error = performChoice(menu());
    }
    while (error >= 0 && !alwaysTerminate);
  }

  private void initAnalysis()
  {
    analysisOptions = new ArrayList<String>();
    sa = new SslAnalysis();
    // if another option for the menu is needed, add another String and update the method performChoice
    analysisOptions.add("Exit");
    analysisOptions.add("Analyse Hosts");
    analysisOptions.add("Update Cipher-Suite-Rating");
    analysisOptions.add("Set time (in hours) to merge entries for hosts in the DB");

    alwaysTerminate = false;
  }
  
  private int performChoice(int choice) {
    switch (choice) {
      case 0: 
        System.out.println("Thanks for using HttpsAnalysis4j. Bye.");
        return -1;
      case 1:
        return sa.start();
      case 2: 
        return sa.updateCipherSuiteRating();
      case 3:
        return sa.setHostMergeTime();
      default:
        return -1;
    }
  }

  public static void main(String[] args)
  {
    Main main = new Main();
    main.run();
  }

}
