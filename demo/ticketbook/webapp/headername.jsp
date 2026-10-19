<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.util.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>HeaderName</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>HeaderName</H1>

	<p>HeaderName testing. Use Burp to send malicious header because browser won't</p> 

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Headers</h3>
				</div>
				<div class="panel-body">
				<%
				    Enumeration names = request.getHeaderNames();
				    while (names.hasMoreElements()) {
				      String name = (String) names.nextElement();
				      Enumeration values = request.getHeaders(name);
				      if (values != null) {
				        while (values.hasMoreElements()) {
				          String value = (String) values.nextElement();
				          out.println("<p>"+name + ": " + value+"</p>");
				        }
				      }
				    }
				%>
				</div>
				<div class="panel-body">
				<%
				    Enumeration pnames = request.getParameterNames();
				    while (pnames.hasMoreElements()) {
				      String pname = (String) pnames.nextElement();
				      String pvalue = request.getParameter(pname);
				      out.println("<p>"+pname + ": " + pvalue+"</p>");
				    }
				%>
				</div>
			</div>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>