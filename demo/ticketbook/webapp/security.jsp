<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Attempted Attack Detected</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<font color="red"><H1>Attempted Attack Detected</H1></font>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-body">
An attempted attack was identified and blocked. Details have been logged and may be part of a further investigation.
Contact <a href="mailto:security@ticketbook.com">security@ticketbook.com</a> to report more information about this attack.
				</div>
			</div>
		</div>
	</div>

<%@ include file="/footer.jsp" %>
</body>

</html>