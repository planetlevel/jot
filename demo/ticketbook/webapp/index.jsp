<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Contrast TicketBook</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<H1>Welcome to TicketBook</H1>
<p class="lead">TicketBook is a vulnerable JavaEE application for learning and testing purposes.</p>
<div class="row home-cards">
	<div class="col-sm-6 col-md-3"><a class="home-card" href="/ticketbook/profile"><h3>Application</h3><p>Register a user and list the tickets.</p></a></div>
	<div class="col-sm-6 col-md-3"><a class="home-card" href="/ticketbook/request.jsp"><h3>Request handling</h3><p>How requests, headers, paths, forwards and includes are handled.</p></a></div>
	<div class="col-sm-6 col-md-3"><a class="home-card" href="/ticketbook/el.jsp"><h3>Vulnerabilities</h3><p>Deliberately vulnerable pages, such as expression injection, XSS, XXE and command injection.</p></a></div>
	<div class="col-sm-6 col-md-3"><a class="home-card" href="/ticketbook/accessA.jsp"><h3>Access control</h3><p>Pages that check roles, so you can switch users and compare.</p></a></div>
</div>
<%@ include file="/footer.jsp" %>
</body>

</html>