<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.net.*"%>
<%@ page import="java.io.*"%>
<%@ page import="nu.xom.Builder"%>
<%@ page import="nu.xom.Document"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Socket</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Socket</H1>

	<%
		Socket s = new Socket( "localhost", 8080 );
	%>	

	<BR>
	<BR>

	<div>File Content:</div>
	<BR>
	<textarea cols='80' rows='25'>
	BLAH
	</textarea>

	<%@ include file="/footer.jsp"%>
</body>

</html>
