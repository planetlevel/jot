<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="com.thoughtworks.xstream.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>XStream Deserialization</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
<script src="/ticketbook/js/loadfile.js"></script>
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>XStream Deserialization</H1>

	<p>XStream turns XML back into Java objects, and the XML names the classes. Before 1.4.18 there was no block list by default, so an attacker could describe objects that run code when they are rebuilt.</p>
	<p>CVE-2021-39144 affects XStream, versions before 1.4.18. The rule <code>cve-2021-39144</code> in <code>cves/CVE-2021-39144.jot</code> lets
	<code>XStream.fromXML</code> run, but blocks it from evaluating an expression, starting a process or running a script.</p>

	<%
		String input = request.getParameter( "input" );
		String result = null;
		if ( input != null ) {
			try {
				XStream xstream = new XStream();
				Object o = xstream.fromXML( input );
				result = "Read a " + o.getClass().getName() + ": " + o;
			} catch ( Throwable t ) {
				result = "Error: " + t;
			}
		}
		if ( input == null ) input = "<string>hello</string>";
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter XML:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" autocomplete="off">
						<div class="form-group">
							<textarea id="input" name="input" rows="6" class="form-control" placeholder="XML"><%=ESAPI.encoder().encodeForHTML(input) %></textarea>
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
