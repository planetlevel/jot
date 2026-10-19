<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="nu.xom.*" %>
<%@ page import="java.io.*"%>
<%@ page import="java.net.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>XML External Entity (XXE) in XOM</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<H1>XML External Entity (XXE) in XOM</H1>

<p>XML external entity attacks are a way of adding a &lt;DOCTYPE&gt; to an XML document and using it to trick a server-side XML
parser into doing things that it wasn't supposed to, like accessing protected files and URLs, and potentially exposing the data they contain.</p>

<% String xmldoc=
	"<?xml version=\"1.0\" ?>\n" +
	"<!DOCTYPE biz [<!ENTITY xxetest1 SYSTEM \"/etc/passwd\">]>\n"+
	"<test>\n   &xxetest1;\n</test>\n";
%>

<div>Enter XML Input:</div><BR>
	<form method="POST" autocomplete="off">
	<textarea rows='8' cols='80' name='xml'><%=xmldoc %></textarea>
	<input type='submit' name='submit' value='Go!'>
	</form>

<%
   String xml = "Enter XML above and hit Go!";
   String param = request.getParameter("xml");
   if ( param != null ) {
	   try {
		   if("GET".equals(request.getMethod())) {
			   out.println( "<div>Please POST an XML document to me in the body!</div>" );
			   return;
			}
		   InputStream is = new ByteArrayInputStream(param.getBytes());

		   Builder builder = new Builder();
		   Document doc = builder.build(is);
		   xml = doc.toXML();		   
	   } catch( Exception e ) {
		   xml = "Error processing document: " + e.getMessage();
	   }
	   
   }
%>

<BR>
<BR>

<div>XML Document After Parsing:</div><BR>
	<textarea cols='80' rows='25'>
	<%=ESAPI.encoder().encodeForHTML(xml)%>
	</textarea>

<%@ include file="/footer.jsp" %>
</body>

</html>