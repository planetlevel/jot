<%@ page import="java.net.*"%>
<%@ page import="java.io.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<%
	String host = "owasp.org";
	int port = 80;
	StringBuilder response2 = new StringBuilder();
	try {
		// the two argument constructor is what the get-sockets sensor watches
		Socket s = new Socket( host, port );
		s.setSoTimeout( 5000 );
		try {
			Writer out2 = new OutputStreamWriter( s.getOutputStream(), "ISO-8859-1" );
			out2.write( "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n" );
			out2.flush();
			BufferedReader reader = new BufferedReader( new InputStreamReader( s.getInputStream(), "ISO-8859-1" ) );
			// the status line and headers, up to the blank line, and not the page
			String line;
			while ( ( line = reader.readLine() ) != null && !line.isEmpty() ) {
				response2.append( line ).append( "\n" );
			}
		} finally {
			s.close();
		}
	} catch ( IOException e ) {
		response2.append( "Could not connect to " ).append( host ).append( ":" ).append( port ).append( ", " ).append( e );
	}
%>

<head>
<title>Socket</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Socket</H1>

	<div>Connected to <%= host %> on port <%= port %>. The response headers:</div>
	<BR>
	<textarea cols='80' rows='25'><%= ESAPI.encoder().encodeForHTML( response2.toString() ) %></textarea>

	<%@ include file="/footer.jsp"%>
</body>

</html>
