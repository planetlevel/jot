<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.yaml.snakeyaml.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>SnakeYAML Deserialization</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
<script src="/ticketbook/js/loadfile.js"></script>
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>SnakeYAML Deserialization</H1>

	<p>The default SnakeYAML constructor lets a YAML tag name any class, so loading untrusted YAML can create any object on the classpath and call its constructor.</p>
	<p>CVE-2022-1471 affects SnakeYAML, versions before 2.0. The rule <code>cve-2022-1471</code> in <code>cves/CVE-2022-1471.jot</code> lets
	<code>Yaml.load</code> run, but blocks it from evaluating an expression, starting a process or running a script.</p>

	<%
		String input = request.getParameter( "input" );
		String result = null;
		if ( input != null ) {
			try {
				Yaml yaml = new Yaml();
				Object o = yaml.load( input );
				result = "Read a " + ( o == null ? "null" : o.getClass().getName() ) + ": " + o;
			} catch ( Throwable t ) {
				result = "Error: " + t;
			}
		}
		if ( input == null ) input = "name: jeff";
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter YAML:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" autocomplete="off">
						<div class="form-group">
							<textarea id="input" name="input" rows="6" class="form-control" placeholder="YAML"><%=ESAPI.encoder().encodeForHTML(input) %></textarea>
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
