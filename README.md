README for Shibboleth Authenticator for Jira 7.x
================================================

Main page at:
https://github.com/UW-Madison-DoIT/jiraRemoteUserAuth

This is a port of the Shibboleth Authenticator for Confluence documentated at:
https://studio.plugins.atlassian.com/wiki/display/SHBL/Confluence+Shibboleth+Authenticator


Compilation (using Atlassian Plugin SDK)
========================================

run "atlas-clean", then "atlas-compile", then "atlas-package"


Shibboleth Deployment
=====================

1) copy the target/jiraRemoteUserAuth-x.x.x.jar to your
   edit-webapp/WEB-INF/lib

2) copy jiraRemoteUserAuthenticator.properties to edit-webapp/WEB-INF/classes
   and configure to your needs

3) modify seraph-config.xml in your jira/WEB-INF/classes accordingly. Below
   shows that login.url has been modified to point to WAYF (or could be your 
   IdP) directly; Logout url points to the server's location of Shibboleth SSO 
   (we use SERVER, change it to whatever your server which hosted 
   jira); have a look at your shibboleth.xml for some entry details... 
   standard jira authenticator has been changed to our 
   JiraWebServerAuthenticator

   -----------------

    <param-name>login.url</param-name>
    <param-value>https://SERVER/Shibboleth.sso/XXX?target=/jira/secure/Dashboard.jspa?os_destination=${originalurl}</param-value>
    
    <param-name>link.login.url</param-name>
    <param-value>https://SERVER/Shibboleth.sso/XXX?target=/jira/secure/Dashboard.jspa?os_destination=${originalurl}</param-value>
    
    <param-name>link.logout.url</param-name>
    <param-value>https://SERVER/Shibboleth.sso/Logout?return=/jira/secure/Logout!default.jspa</param-value>
    
    <param-name>logout.url</param-name>
    <param-value>https://SERVER/Shibboleth.sso/Logout?return=/jira/secure/Logout!default.jspa</param-value>
    
    <!-- <authenticator class="com.atlassian.seraph.auth.DefaultAuthenticator"/> -->
    <authenticator class="shibauth.jira.authentication.shibboleth.RemoteUserAuthenticator"/>

   -----------------

4) configure your SP AAP.xml or attribute-map.xml by mapping appropriate headers (pay attention to step #2).
   
   Most likely headers you need: 
   * REMOTE_USER
   * FULL_NAME
   * EMAIL
   * whatever dynamic roles' headers

5) modification on apache's configuration
  
  a) configure mod_proxy_ajp

    ProxyPass /jira ajp://localhost:8009/jira
    <Proxy ajp://localhost:8009/jira>
      Order deny,allow
      Allow from all
    </Proxy>
  
  b) export headers, and protect jira with shib lazy session
  
     <Location /jira>
        AuthType shibboleth
        ShibRequireSession Off
        ShibUseHeaders On
        require shibboleth
     </Location>

   or regular session

     <Location /jira>
        AuthType shibboleth
        ShibRequireSession On
        ShibUseHeaders On
        require shibboleth
     </Location>

6) modify tomcat's server.xml entry to include (find where port 8009 and copy
   it into below). if you're using tomcat5.5 or above, you may want to put
   tomcatAuthentication="false" entry and strip the "request." section. This has
   changed in recent tomcat, refer to your tomcat manual for detail.

<Connector port="8009"
           tomcatAuthentication="false"
           address="127.0.0.1" 
           enableLookups="false"
           redirectPort="8443"
           protocol="AJP/1.3" />


7) restart tomcat and try to click on the login link

