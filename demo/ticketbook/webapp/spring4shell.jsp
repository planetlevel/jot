<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.springframework.beans.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Spring4Shell</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
<script src="/ticketbook/js/loadfile.js"></script>
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Spring4Shell</H1>

	<p>Spring binds request parameters to bean properties by name. When the property name comes from the user, they can walk through the bean's class to objects it should never expose. The bean introspection code is where this goes wrong.</p>
	<p>CVE-2022-22965 affects Spring Framework (spring-beans), versions before 5.2.20. The rule <code>cve-2022-22965</code> in <code>cves/CVE-2022-22965.jot</code> lets
	<code>CachedIntrospectionResults.introspectInterfaces</code> run, but blocks it from evaluating an expression, starting a process or running a script.</p>

	<%!
		public static class Ticket {
			private String title;
			public String getTitle() { return title; }
			public void setTitle( String title ) { this.title = title; }
		}
	%>

	<%
		String input = request.getParameter( "input" );
		String result = null;
		if ( input != null ) {
			try {
				String value = request.getParameter( "value" );
				if ( value == null ) value = "";
				BeanWrapperImpl wrapper = new BeanWrapperImpl( new Ticket() );
				wrapper.setPropertyValue( input, value );
				result = "Set " + input + " to " + value;
			} catch ( Throwable t ) {
				result = "Error: " + t;
			}
		}
		if ( input == null ) input = "title";
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter a property name and value:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" autocomplete="off">
						<div class="form-group">
							<input id="input" name="input" value="<%=ESAPI.encoder().encodeForHTML(input) %>" class="form-control" placeholder="property name">
						</div>
						<div class="form-group">
							<input id="value" name="value" value="" class="form-control" placeholder="value">
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
