<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Unchecked Forward</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<%
	String param = request.getParameter( "page" );
%>

<body>
<%@ include file="/menu.jsp" %>
<H1>Unchecked Forward</H1>

<p>Unchecked forwards happen when untrusted data is used in a server-side forward. The attacker can use an unchecked forward to
bypass security constraints that prevent them from reaching certain pages.</p>

<div>Enter forward page:</div><BR>
	<form method="POST" action="forward.jsp" autocomplete="off">
	<input name='page' value='admin.jsp'>
	<input type='submit' name='submit' value='Go!'>
	</form>

<%
	if ( param != null ) {
		RequestDispatcher dispatcher = request.getRequestDispatcher(param);
		dispatcher.forward(request, response);
	}
%>

<%@ include file="/footer.jsp" %>
</body>

</html>