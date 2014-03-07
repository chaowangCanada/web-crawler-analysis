Description:
============
HttpsChecker4j is a tool to be used in conjunction with HttpCrawler4j. 
It scans SSL-hosts, found by HttpCrawler4j regarding TLS-security. 
SSL-hosts to scan are taken from, and results are stored into the MySQL database called crawler. 

HttpsAnalysis4j is a tool to analyze the scanning-results from HttpsChecker4j and generating HTML output with all results.
This covers the security assessment and rating of all ciphersuites that are supported by each processed SSL-host.

TLS-Background
--------------
A TLS-handshake (was former SSL) is used to establish secure http-connections (https) to webservers.
In principle the handshake works as follows:

Client (Browser)                    Server
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

Setup:
======
* install openssl. If you need SSLv2, you need to compile your own version. See http://www.hackwhackandsmack.com/?p=46
* compile and install sslscan. Make sure you have installed the right version by typing:
    sslscan --version       //required version = 1.8.2_t
  This version of sslscan also supports TLSv1.1 and TLSv1.2 and provides a flag for limiting the speed of connection attempts to one host.
* Install maven
* Create HttpsChecker4j Eclipse project:
    mvn eclipse:eclipse
    Manually add classpath and dependency to database

Run:
====
* run HttpCrawler4j first or provide a file with hosts to scan
* adapt src/database.properties
* run HttpsChecker4j with specified commandline options. Use --help to display commandline options.
* failures.txt contains hosts that produced an error.
