1587038396

sean@reims> jq 'select(.src_addr=="145.100.111.82") | .msg' /var/log/snort/alert_json.txt | sort | uniq
"(http_inspect) not HTTP traffic"
"(http_inspect) server response before client request"
"(ipv4) IPv4 option set"
"(ipv4) IPv4 packet to broadcast dest address"
"(port_scan) IP filtered protocol sweep"
"(port_scan) TCP portsweep"
"(port_scan) UDP filtered portsweep"
"(port_scan) UDP portsweep"
"(stream_tcp) TCP timestamp is missing"
"(stream_tcp) data sent on stream after TCP reset received"
"(stream_tcp) data sent on stream after TCP reset sent"
"(stream_tcp) data sent on stream not accepting data"
"(stream_tcp) reset outside window"
"HTTP login error"
"HTTP login success"
"HTTP server response"
"INDICATOR-COMPROMISE 403 Forbidden"
"INDICATOR-COMPROMISE Invalid URL"
"MSSQL response"
"MSSQL select"
"MSSQL server response"
"MSSQL"
"PROTOCOL-ICMP Echo Reply"
"SQL ping attempt"
"SQL sa brute force failed login unicode attempt"
"http"

arccy@nevers> nmap -sC 145.100.111.82
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-16 13:59 CEST
Nmap scan report for 145.100.111.82
Host is up (0.0013s latency).
Not shown: 999 filtered ports
PORT STATE SERVICE
80/tcp open http
| http-methods:
|\_ Potentially risky methods: TRACE
|\_http-title: OT Lab

Nmap done: 1 IP address (1 host up) scanned in 8.50 seconds

arccy@nevers> nmap --script discovery,exploit,vuln ot.uva.davidepucci.it
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-16 13:52 CEST
Pre-scan script results:
| targets-asn:
|_ targets-asn.asn is a mandatory parameter
Stats: 0:02:12 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.24% done; ETC: 13:55 (0:00:01 remaining)
Stats: 0:02:41 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.81% done; ETC: 13:55 (0:00:00 remaining)
Nmap scan report for ot.uva.davidepucci.it (145.100.111.82)
Host is up (0.0014s latency).
Not shown: 999 filtered ports
PORT STATE SERVICE
80/tcp open http
|\_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-auth-finder:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=ot.uva.davidepucci.it
| url method
| http://ot.uva.davidepucci.it:80/ FORM
|_ http://ot.uva.davidepucci.it:80/index.php FORM
|_http-chrono: Request times for /; avg: 177.70ms; min: 162.65ms; max: 208.02ms
|\_http-comments-displayer: Couldn't find any comments.
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=ot.uva.davidepucci.it
| Found the following possible CSRF vulnerabilities:
|
| Path: http://ot.uva.davidepucci.it:80/
| Form id: username
| Form action: index.php
|
| Path: http://ot.uva.davidepucci.it:80/index.php
| Form id: username
|_ Form action: index.php
|_http-date: Thu, 16 Apr 2020 09:53:06 GMT; -2h00m16s from local time.
|\_http-devframework: ASP.NET detected. Found related header.
|\_http-dombased-xss: Couldn't find any DOM based XSS.
|\_http-errors: Couldn't find any error pages.
|\_http-feed: Couldn't find any feeds.
| http-headers:
| Content-Length: 0
| Content-Type: text/html; charset=UTF-8
| Server: Microsoft-IIS/7.5
| X-Powered-By: PHP/5.6.0
| X-Powered-By: ASP.NET
| Date: Thu, 16 Apr 2020 09:53:09 GMT
| Connection: close
|
|_ (Request type: HEAD)
|_http-mobileversion-checker: No mobile version detected.
|\_http-php-version: Version from header x-powered-by: PHP/5.6.0, ASP.NET
|\_http-referer-checker: Couldn't find any cross-domain scripts.
|\_http-security-headers:
| http-sitemap-generator:
| Directory structure:
| /
| Other: 1; css: 1; php: 1
| Longest directory structure:
| Depth: 0
| Dir: /
| Total files found (by extension):
|_ Other: 1; css: 1; php: 1
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|\_http-title: OT Lab
| http-useragent-tester:
| Status for browser useragent: 200
| Allowed User Agents:
| Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
| libwww
| lwp-trivial
| libcurl-agent/1.0
| PHP/
| Python-urllib/2.5
| GT::WWW
| Snoopy
| MFC_Tear_Sample
| HTTP::Lite
| PHPCrawl
| URI::Fetch
| Zend_Http_Client
| http client
| PECL::HTTP
| Wget/1.13.4 (linux-gnu)
|_ WWW-Mechanize/1.34
| http-vhosts:
|\_127 names had status 200
|\_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|\_http-xssed: No previously reported XSS vuln.

Host script results:
|_asn-query: No Answers
| dns-brute:
|_ DNS Brute-force hostnames: No results.
|_fcrdns: FAIL (No PTR record)
| hostmap-crtsh:
|_ subdomains: Error: found no hostnames but not the marker for "name*value" (pattern error?)
|\_hostmap-robtex: ERROR: Script execution failed (use -d to debug)
| ip-geolocation-geoplugin:
|\_145.100.111.82 (ot.uva.davidepucci.it)
| resolveall:
| Host 'ot.uva.davidepucci.it' also resolves to:
| Use the 'newtargets' script-arg to add the results as targets
|* Use the --resolve-all option to scan all resolved addresses without using this script.
| whois-domain:
|
| Domain name record found at whois.nic.it
| Domain: ot.uva.davidepucci.it
| Status: UNASSIGNABLE
|\_
| whois-ip: Record found at whois.ripe.net
| inetnum: 145.100.96.0 - 145.100.111.255
| netname: UvA-Master-SNE-NET
| descr: Universiteit van Amsterdam
|\_country: NL

Nmap done: 1 IP address (1 host up) scanned in 161.77 seconds
