<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.apache.commons.text.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Text4Shell</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
<script src="/ticketbook/js/loadfile.js"></script>
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Text4Shell</H1>

	<p>The default string interpolator in Commons Text can resolve script, DNS and URL lookups written into the text it is given. When untrusted data is substituted, the attacker chooses the lookup.</p>
	<p>CVE-2022-42889 affects Apache Commons Text, versions 1.5 up to 1.10.0. The rule <code>cve-2022-42889</code> in <code>cves/CVE-2022-42889.jot</code> lets
	<code>StringSubstitutor.replace</code> run, but blocks it from evaluating an expression, starting a process or running a script.</p>

	<%
		String input = request.getParameter( "input" );
		String result = null;
		if ( input != null ) {
			try {
				StringSubstitutor interpolator = StringSubstitutor.createInterpolator();
				result = interpolator.replace( input );
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
					<h3 class="panel-title">Enter text to substitute:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" autocomplete="off">
						<div class="form-group">
							<input id="input" name="input" value="<%=ESAPI.encoder().encodeForHTML(input) %>" class="form-control" placeholder="text">
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
