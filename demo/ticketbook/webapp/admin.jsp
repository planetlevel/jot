<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.owasp.esapi.codecs.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Administration Page</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Administration Page</H1>

	<p>This page is protected by a security-constraint in web.xml and shouldn't be accessible without the ADMIN role. In particular, the
	'protocol' parameter is particularly sensitive.</p> 

	<%
		String protocol = request.getParameter( "protocol" );
		if ( protocol != null ) {
			out.println( "<p><span class=\"text-danger\">DANGER</span>: Setting protocol to <span class=\"text-danger\">"+protocol+"</span></p>");
	    }
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Super secret administrative functions</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="admin.jsp" autocomplete="off">
						<div class="form-group">
							<input name="protocol" id="protocol" value="post hoc ergo propter hoc" class="form-control" placeholder="data">
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