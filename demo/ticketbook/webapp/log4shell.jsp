<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.apache.logging.log4j.LogManager"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Log4Shell</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
<script src="/ticketbook/js/loadfile.js"></script>
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Log4Shell</H1>

	<p>Log4j looks inside every message it logs for lookup patterns and resolves them. When untrusted data is logged, the attacker chooses which lookup runs. The JNDI lookup can then be pointed at a server they control.</p>
	<p>CVE-2021-44228 affects Apache Log4j, versions 2.13.0 up to 2.15.0. The rule <code>cve-2021-44228</code> in <code>cves/CVE-2021-44228.jot</code> stops
	<code>JndiLookup.lookup</code> from making a JNDI lookup, evaluating an expression, starting a process or running a script.</p>

	<%
		String input = request.getParameter( "input" );
		String result = null;
		if ( input != null ) {
			try {
				org.apache.logging.log4j.Logger logger = LogManager.getLogger( "ticketbook" );
				logger.error( input );
				result = "Logged " + input.length() + " characters.";
			} catch ( Throwable t ) {
				result = "Error: " + t;
			}
		}
		if ( input == null ) input = "hello";
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter a message to log:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" autocomplete="off">
						<div class="form-group">
							<input id="input" name="input" value="<%=ESAPI.encoder().encodeForHTML(input) %>" class="form-control" placeholder="message">
						</div>
						<button name="submit" type="submit" class="btn btn-warning">Submit</button>
						<button id="loadbutton" type="button" class="btn btn-default">Load from file</button>
						<input id="loadfile" type="file" style="display:none">
					</form>
				</div>
			</div>
		</div>
	</div>

	<% if ( result != null ) { %>
	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Result</h3>
				</div>
				<div class="panel-body">
					<div><%=ESAPI.encoder().encodeForHTML( result ) %></div>
				</div>
			</div>
		</div>
	</div>
	<% } %>

	<%@ include file="/footer.jsp"%>
</body>

</html>
