<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Internal Error</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<H1>Internal Error</H1>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-body">
				An unknown error occurred. Please try again.
				</div>
			</div>
		</div>
	</div>

<%@ include file="/footer.jsp" %>
</body>

</html>