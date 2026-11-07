<%@ page import="com.acme.ticketbook.idor.*"%>
<%@ page import="java.util.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>IDOR</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Insecure direct object reference</H1>

	<p>Every booking belongs to one user, and each level hands its owner a different kind of id for it. Sign in as one user and get at a
	booking that belongs to another. Every level can be reached through the query string, a form field, a path segment, a header, a cookie
	or a JSON body, and the actions that change something answer only "Action complete" unless you ask them to say more. The
	<a href="/ticketbook/outbox.jsp">outbox</a> shows what actually happened.</p>

	<%
		IdorStore store = new IdorStore();
		String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : (String) session.getAttribute("idor.user");
		String mode = session.getAttribute("idor.mode") == null ? "vulnerable" : (String) session.getAttribute("idor.mode");
		boolean visible = Boolean.TRUE.equals(session.getAttribute("idor.visible"));
	%>

	<div class="row">
		<div class="col-md-6">
			<div class="panel panel-primary">
				<div class="panel-heading"><h3 class="panel-title">Signed in as <%= user == null ? "nobody" : IdorStore.esc(user) %></h3></div>
				<div class="panel-body">
					<form method="POST" action="/ticketbook/idor/login">
						<% for (String u : IdorStore.USERS) { %>
						<button name="user" type="submit" value="<%= u %>" class="btn btn-warning"><%= u %></button>
						<% } %>
					</form>
				</div>
			</div>
		</div>
		<div class="col-md-6">
			<div class="panel panel-primary">
				<div class="panel-heading"><h3 class="panel-title">Settings</h3></div>
				<div class="panel-body">
					<form method="POST" action="/ticketbook/idor/settings" class="form-inline">
						<select name="mode" class="form-control">
							<option value="vulnerable"<%= mode.equals("vulnerable") ? " selected" : "" %>>Vulnerable</option>
							<option value="patched"<%= mode.equals("patched") ? " selected" : "" %>>Patched, checks the signed-in name</option>
							<option value="context"<%= mode.equals("context") ? " selected" : "" %>>Patched, checks the SecurityContext in the session</option>
						</select>
						<select name="feedback" class="form-control">
							<option value="blind"<%= visible ? "" : " selected" %>>Blind, "Action complete"</option>
							<option value="visible"<%= visible ? " selected" : "" %>>Says what it did</option>
						</select>
						<button type="submit" class="btn btn-default">Set</button>
					</form>
					<form method="POST" action="/ticketbook/idor/reset" style="margin-top:8px">
						<button type="submit" class="btn btn-default btn-sm">Reset the bookings and the outbox</button>
					</form>
				</div>
			</div>
		</div>
	</div>

	<% if (user != null) {
		List<Doc> mine = store.mine(user);
	%>
	<div class="panel panel-primary">
		<div class="panel-heading"><h3 class="panel-title">Your bookings</h3></div>
		<div class="panel-body">
			<table class="table">
				<tr><th>Booking</th><th>Status</th></tr>
				<% for (Doc d : mine) { %>
				<tr><td><%= IdorStore.esc(d.subject) %></td><td><%= IdorStore.esc(d.status) %></td></tr>
				<% } %>
			</table>
			<% if (!mine.isEmpty()) { Doc first = mine.get(0); %>
			<p>This is what the application gives you to send back for <b><%= IdorStore.esc(first.subject) %></b> in each level and channel.</p>
			<table class="table">
				<tr><th>Level</th><% for (String ch : new String[] { "query", "form", "path", "header", "cookie", "json" }) { %><th><%= ch %></th><% } %></tr>
				<% for (int level = 1; level <= 3; level++) { %>
				<tr><td><%= level %></td>
					<% for (String ch : new String[] { "query", "form", "path", "header", "cookie", "json" }) { %>
					<td><code><%= IdorStore.esc(IdorLinks.id(level, ch, first)) %></code></td>
					<% } %>
				</tr>
				<% } %>
			</table>
			<% } %>
		</div>
	</div>
	<% } %>

	<div class="panel panel-primary">
		<div class="panel-heading"><h3 class="panel-title">Try a request</h3></div>
		<div class="panel-body">
			<form id="try" class="form-inline" onsubmit="return false">
				<select id="level" class="form-control"><option>1</option><option>2</option><option>3</option></select>
				<select id="op" class="form-control"><option>read</option><option>update</option><option>close</option><option>delete</option><option>mail</option></select>
				<select id="channel" class="form-control"><option>query</option><option>form</option><option>path</option><option>header</option><option>cookie</option><option>json</option></select>
				<input id="value" class="form-control" size="40" placeholder="the id, as that channel carries it">
				<input id="extra" class="form-control" size="24" placeholder="text or to address (optional)">
				<button id="go" class="btn btn-default">Send</button>
			</form>
			<pre id="result" style="margin-top:10px">The response shows here.</pre>
		</div>
	</div>

	<script>
	document.getElementById("go").onclick = function () {
		var level = document.getElementById("level").value, op = document.getElementById("op").value;
		var ch = document.getElementById("channel").value, v = document.getElementById("value").value;
		var extra = document.getElementById("extra").value;
		var key = op === "mail" ? "to" : "text";
		var url = "/ticketbook/idor/" + level + "/" + op + "/" + ch, init = { credentials: "same-origin", headers: {} };
		if (ch === "query") { url += "?id=" + encodeURIComponent(v) + (extra ? "&" + key + "=" + encodeURIComponent(extra) : ""); }
		else if (ch === "form") { init.method = "POST"; init.headers["Content-Type"] = "application/x-www-form-urlencoded";
			init.body = "id=" + encodeURIComponent(v) + (extra ? "&" + key + "=" + encodeURIComponent(extra) : ""); }
		else if (ch === "path") { url += "/" + v + (extra ? "?" + key + "=" + encodeURIComponent(extra) : ""); }
		else if (ch === "header") { init.headers["X-Ticket-Id"] = v; url += extra ? "?" + key + "=" + encodeURIComponent(extra) : ""; }
		else if (ch === "cookie") { document.cookie = "ticket=" + v + "; path=/ticketbook/idor"; url += extra ? "?" + key + "=" + encodeURIComponent(extra) : ""; }
		else { init.method = "POST"; init.headers["Content-Type"] = "application/json"; init.body = v; }
		fetch(url, init).then(function (r) { return r.text().then(function (t) { document.getElementById("result").textContent = r.status + " " + t; }); });
	};
	</script>

	<%@ include file="/footer.jsp"%>
</body>

</html>
