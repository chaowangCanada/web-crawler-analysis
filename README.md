web-crawler-analysis
====================

## First Start
* install maven
* install mysql database (on localhost!)
* you may need to install the Spring Framework
* setup configfile: ./Analysis/src/main/resources/database.properties
* setup configfile: ./HttpCrawler4j/src/database.properties
* config seeds: ./HttpCrawler4j/src/seeds.txt
* config whitelist (urls that start with these are always crawled): ./HttpCrawler4j/src/url-whitelist.txt
* Verify that on building projects, all these config files must be deployed
* Include all other config files, e.g. in ./crawler4j/src/main/resources/
* On the first run of the HttpCrawler4j the database is generated automatically
* In the file ./sql-commands.txt you find usefull SQL commands.

## Subprojects
* crawler4j: fork of the crawler4j project by Yasser Ganjisaffar with minor changes
* HttpCrawler4jDatabase: database configuration using Resthub
* HttpCrawler4j: Executable project that crawls the web and stores Metadata to database
* Analysis: After Crawling you can use this project to analyse the crawled data. The results are exported to html files.

## Licence
For Licence details please see licence.txt in the root folder and in each subfolder.

## Compiling Problems
1. Check database.properties in both folders: HttpCrawler4j and analysis!
2. Check if MySQL is running:
  mysql -u crawler -o crawler
3. mvn clean install           (on crawler4j and HttpCrawlerDatabase)
4. mvn eclipse:eclipse         (on analysis and HttpCralwer4j)
5. make sure the config files are added to the build
  (Eclipse: right click on project -> Properties -> Java Build Path -> Source
  check included and excluded for the files where the config files are!)
  Else you could get internal errors in the project or errors with RestHub)
6. analysis-program needs write permission to a given folder (e.g. /analysis/export/)
7. other maven problems:
  Maven Problems solved: do exactly what they do there:
  http://www.avajava.com/tutorials/lessons/how-do-i-add-a-project-as-a-dependency-of-another-project.html?page=2

## Config Files
* /HttpCrawler4j/src/database.properties
* /HttpCrawler4j/src/headers-blacklist.txt
* /HttpCrawler4j/src/seeds.txt
* /HttpCrawler4j/src/url-whitelist.txt
* /analysis/src/main/resources/database.properties
* /analysis/src/main/resources/evcerts.txt


## Crawling Policy
1. Every Host is only once crawled as the link is found in any other page but only if it's the first visit to this host.
2. Except if the URL starts with a String in the url-whitelist.txt (not case sensititve)
3. If you get a http URL to the links, we also try to visit the page as https.
4. The crawler starts with the seeds given in seeds.txt
5. You may want to have this seeds in the whitelist.
6. We respect the robots.txt file. If this file forbids our crawler, we do not use it.
7. We have a politeness delay (niceWaitTime): the host is not visited twice until this time interval (set in HttpAnalysisCrawler - the other one is not working!).
8. The crawler follows redirects.
9. It is possible to set a max depth of crawling (deactivated). (set in HttpAnalysisCrawlController)
10. The socket timeout and the connection timeout can be set in HttpAnalysisCrawlController.
11. Crawler is multithreaded. Has still to be tested how many pages at once are feasible.
12. different priorities for HTTPS/HTTP-pages are possible and respected. Also a different priority for the Whitelist.
  I used 10 for the whitelist and 5 for http/https. Hence the whitelisted-urls are visited last and the queue wont get too large.
13. Hint: do not use brackets () in your (absolute) path or maven builds will fail.

# Resolve Problems
If you have problems with maven dependencies between projects do exactly what it says here in the console:
http://www.avajava.com/tutorials/lessons/how-do-i-add-a-project-as-a-dependency-of-another-project.html?page=2

* e.g in ./HttpCrawler4jDatabase: mvn install
* e.g in ./crawler4j: mvn install
* e.g in ./HttpCrawler4j/database: mvn eclipse:eclipse
* e.g in ./Analysis: mvn eclipse:eclipse
