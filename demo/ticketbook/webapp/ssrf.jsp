<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.owasp.esapi.codecs.*"%>
<%@ page import="java.net.*"%>
<%@ page import="java.io.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<%
	String param = request.getParameter("urlparam");
	StringBuilder content = new StringBuilder();
	if ( param != null ) {
		System.err.println( "GETTING: " + param );
		URL url = new URL( param );
		URLConnection conn = url.openConnection();
		try {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
                    String line;
                    while ((line = reader.readLine()) != null)
                    {
                      content.append(line);
                    }
                    reader.close();
                } catch( Exception e ) {
		    e.printStackTrace();
	        }
	}
%>

<head>
<title>SSRF</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>SSRF</H1>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter a URL</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="ssrf.jsp" autocomplete="off">
						<div class="form-group">
							<input name="urlparam" id="cmd" value="Calculator" class="form-control" placeholder="data">
						</div>
						<button name="submit" type="submit" class="btn btn-warning">Submit</button>
					</form>
				</div>
			</div>
		</div>
	</div>

	<pre><%=content.toString()%></pre>

	<%@ include file="/footer.jsp"%>
</body>

</html>
