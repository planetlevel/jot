<%@ page import="com.acme.ticketbook.idor.*"%>
<%@ page import="java.util.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Outbox</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Outbox</H1>

	<p>Mail the application sent for the <a href="/ticketbook/idor.jsp">IDOR exercise</a>, as if this page were the mailbox of whoever the mail
	was sent to. The bookings below it are the instructor view, with the owner and status of every one.</p>

	<%
		IdorStore store = new IdorStore();
	%>

	<div class="panel panel-primary">
		<div class="panel-heading"><h3 class="panel-title">Sent mail</h3></div>
		<div class="panel-body">
			<table class="table">
				<tr><th>To</th><th>Sent by</th><th>Subject</th><th>Body</th></tr>
				<% for (String[] m : store.outbox()) { %>
				<tr><td><%= IdorStore.esc(m[1]) %></td><td><%= IdorStore.esc(m[2]) %></td><td><%= IdorStore.esc(m[3]) %></td><td><%= IdorStore.esc(m[4]) %></td></tr>
				<% } %>
			</table>
		</div>
	</div>

	<div class="panel panel-primary">
		<div class="panel-heading"><h3 class="panel-title">Instructor view, every booking</h3></div>
		<div class="panel-body">
			<table class="table">
				<tr><th>Id</th><th>Number</th><th>Ref</th><th>Owner</th><th>Status</th><th>Body</th></tr>
				<% for (Doc d : store.all()) { %>
				<tr><td><%= d.id %></td><td><%= IdorStore.esc(d.number) %></td><td><%= IdorStore.esc(d.ref) %></td><td><%= IdorStore.esc(d.owner) %></td><td><%= IdorStore.esc(d.status) %></td><td><%= IdorStore.esc(d.body) %></td></tr>
				<% } %>
			</table>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>
