<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="com.fasterxml.jackson.databind.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Jackson Deserialization</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
<script src="/ticketbook/js/loadfile.js"></script>
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Jackson Deserialization</H1>

	<p>With default typing switched on, Jackson reads the class to create from the JSON itself. An attacker picks a class that does something dangerous when it is configured, and the parser builds it for them.</p>
	<p>CVE-2019-12384 affects jackson-databind, versions 2.9.0 up to 2.9.9.1. The rule <code>cve-2019-12384</code> in <code>cves/CVE-2019-12384.jot</code> lets
	<code>ObjectMapper.readValue</code> run, but blocks it from evaluating an expression, starting a process or running a script.</p>

	<%
		String input = request.getParameter( "input" );
		String result = null;
		if ( input != null ) {
			try {
				ObjectMapper mapper = new ObjectMapper();
				mapper.enableDefaultTyping();
				Object o = mapper.readValue( input, Object.class );
				result = "Read a " + o.getClass().getName() + ": " + o;
			} catch ( Throwable t ) {
				result = "Error: " + t;
			}
		}
		if ( input == null ) input = "[\"java.util.HashMap\",{\"name\":\"jeff\"}]";
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter JSON:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" autocomplete="off">
						<div class="form-group">
							<textarea id="input" name="input" rows="6" class="form-control" placeholder="JSON"><%=ESAPI.encoder().encodeForHTML(input) %></textarea>
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
