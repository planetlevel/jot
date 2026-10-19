<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.owasp.esapi.codecs.*"%>
<%@ page import="java.net.*"%>
<%@ page import="java.io.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<%
	String param = request.getParameter("cmd");
	String[] params = request.getParameterValues("cmd");
	if ( param != null ) {
		String command = "/usr/bin/open -a " + param;
		System.err.println( "Execing: " + command );
		Runtime.getRuntime().exec( command );
//		URL url = new URL( "https://google.com" );
//		URLConnection conn = url.openConnection();
//		try {
//                  BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
//                    String line;
//                    while ((line = reader.readLine()) != null)
//                    {
//                      System.out.println(line);
//                    }
//                    reader.close();
//                } catch( Exception e ) {
//		    e.printStackTrace();
//	        }
	}

	String admin = request.getParameter("admin");

%>

<head>
<title>Command Injection</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Command Injection</H1>

	<p>Command Injection happens when untrusted data is added is sent to an API designed to launch an operating system executable.
	Untrusted data often comes from the HTTP request parameters, headers, or cookies. But it can also come from your session, database, or other server-side sources.</p> 

	<% if (admin != null) { %>
	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">ADMIN CONSOLE - run privileged command</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="cmd.jsp" autocomplete="off">
						<div class="form-group">
							<input name="cmd" id="cmd" value="Calculator" class="form-control" placeholder="data">
						</div>
						<button name="submit" type="submit" class="btn btn-warning">Submit</button>
					</form>
				</div>
			</div>
		</div>
	</div>
	<% } %>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter an OS command</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="cmd.jsp" autocomplete="off">
						<div class="form-group">
							<input name="cmd" id="cmd" value="Calculator" class="form-control" placeholder="data">
						</div>
						<button name="submit" type="submit" class="btn btn-warning">Submit</button>
					</form>
				</div>
			</div>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>
