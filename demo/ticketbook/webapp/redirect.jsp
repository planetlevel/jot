<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="java.io.*" %>
<%@ page import="nu.xom.Builder" %>
<%@ page import="nu.xom.Document" %>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Unchecked Redirect</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<H1>Unchecked Redirect</H1>

<p>An unchecked redirect means that untrusted data is being used in a redirect response sent to the browser. The attacker can use 
this functionality to redirect innocent users to malicious websites, misleading them with a legitimate-looking URL.</p>

<div>Enter a URL:</div><BR>
	<form method="POST" action="redirect.jsp" autocomplete="off">
	<input name='url' value='index.jsp'>
	<input type='submit' name='submit' value='Go!'>
	</form>

<%
	String param = request.getParameter( "url" );
	session.setAttribute( "URL", param );

	// lots more code...
	
	String url = (String)session.getAttribute("URL");
	if ( url != null && url.length() > 0 ) {
	    response.sendRedirect( url );
	}
%>

<%@ include file="/footer.jsp" %>
</body>

</html>