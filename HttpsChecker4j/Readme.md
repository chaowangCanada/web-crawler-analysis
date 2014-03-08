Description:
============
HttpsChecker4j is a tool to be used in conjunction with HttpCrawler4j. 
It scans SSL-hosts, found by HttpCrawler4j regarding TLS-security. 
SSL-hosts to scan are taken from, and results are stored into the MySQL database called crawler. 

HttpsAnalysis4j is a tool to analyze the scanning-results from HttpsChecker4j and generating HTML output with all results.
This covers the security assessment and rating of all ciphersuites that are supported by each processed SSL-host.

TLS-Background
--------------
A TLS (SSL) handshake is used to establish secure http-connections (https) to webservers.
In principle the handshake works as follows:

Client (Browser)                    Server
--------------------------------------------
send ClientHello       ----->        
(offers all supported
ciphersuites)
                       <-----       ServerHello
                                    (Server selects one ciphersuite it supports
                                    and optionally adds key-exchange data)

    Key agreement and switch to encrypted traffic
    
A ciphersuite consists of a
* Authentication+KeyExchange:         Method for authentication and key exchange/agreement
* Bulk cipher:                        symmetric cipher for encrypting content. Provides confidentiality.
* Hash:                               Provides data integrity.

HttpsChecker4j Setup:
=====================
* install openssl. If you need SSLv2, you need to compile your own version. See http://www.hackwhackandsmack.com/?p=46
* compile and install the provided version of sslscan. Make sure you have installed the right version by typing:
    sslscan --version       //required version = 1.8.2_t
  This version of sslscan also supports TLSv1.1 and TLSv1.2 and provides a flag for limiting the speed of connection attempts to one host.
* Install maven
* Create HttpsChecker4j Eclipse project:
    mvn eclipse:eclipse
    Manually add classpath and dependency to database, etc. to this Eclipse project
* Make sure that the HashSets in HostSslInfo are lazily fetched instead of eager fetching.
  (Note that for running HttpsAnalysis4j the HashSets must be eager fetched.)
* adapt src/database.properties, src/host-blacklist.txt, etc.
  
HttpsChecker4j Run:
===================
* run HttpCrawler4j first in order to fill the database with hosts and ssl-hosts.
  Optionally you can provide a file (i.e. src/hostlist.txt) with hosts to be scanned instead.
* run HttpsChecker4j with specified commandline options. Use --help to display commandline options.
* All scanned SSL-hosts will be stored in the database.
* Note: Some hosts do not respond or extremely slow-down multiple connection attempts done by HttpsChecker4j. 
        In order to finish, you can type "abort" to kill these blocked threads and finish the tool. 
        If you type "abort" HttpsChecker4j will wait another max. timeout before the threads are killed. 
        This timeout can be 15min or more, depending on wait-time and number of TLS-versions that are scanned.
        Note that java actually only kills the java threads running in the VM but not the sslscan tools that 
        are also blocked. You can kill them by executing "sudo killall sslscan" in the commandline.
* failures.txt will contain all hosts that produced an error and thus could not be scanned. 
  They don't appear in the database.
