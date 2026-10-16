<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.util.*"%>
<%@ page import="java.sql.*"%>
<%@ page import="javax.naming.*"%>
<%@ page import="javax.naming.directory.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>

<html>

<head>
<title>Architecture</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<H1>Architecture</H1>
<p class="lead">Accessing various backend services and other components</p>  

<p>Spring</p>
<% Class.forName( "org.springframework.security.core.context.SecurityContext" ); %>

<p>Database</p>
<% try {
      String url = "jdbc:oracle:oci:@HR";
      Connection conn = DriverManager.getConnection (url, null);
   } catch (Exception e) { out.println( e.getMessage() ); }
%>

<p>LDAP</p>
<% try {
      Hashtable<String, String> env = new Hashtable<String, String>();
      env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
      env.put(Context.PROVIDER_URL, "ldap://localhost:389/");
      env.put(Context.SECURITY_PRINCIPAL, "user");
      env.put(Context.SECURITY_CREDENTIALS, "pw" );
      new InitialContext(env);
   } catch (Exception e) { out.println( e.getMessage() ); }
%>
<%@ include file="/footer.jsp" %>
</body>

</html>
