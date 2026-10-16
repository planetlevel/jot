<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.net.*" %>
<%@ page import="java.io.*" %>
<%@ page import="javax.xml.parsers.*" %>
<%@ page import="org.w3c.dom.*" %>
<%@ page import="javax.xml.transform.*" %>
<%@ page import="javax.xml.transform.dom.*" %>
<%@ page import="javax.xml.transform.stream.*" %>

<%@ page import="org.xml.sax.*" %>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>XML External Entity (XXE)</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<H1>XML External Entity (XXE)</H1>

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
		   DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();

//		   // Safe! Don't allow users to control the DOCTYPE or specify external entities! */
//		   docBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
//		   docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		    
		   DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
		   InputSource is = new InputSource(new ByteArrayInputStream(param.getBytes()));
//		   InputSource is = new InputSource(request.getInputStream());
		   Document doc = docBuilder.parse(is);
		   
		   Transformer transformer = TransformerFactory.newInstance().newTransformer();
		   StringWriter writer = new StringWriter();
		   transformer.transform(new DOMSource(doc), new StreamResult(writer));
		   xml = writer.getBuffer().toString();
		   
	   } catch( SAXParseException e ) {
		   xml = "Suspected attack. XML document contained a DOCTYPE.";
		   e.printStackTrace();
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
