<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="javax.crypto.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Access Control Testing</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Endpoint D</H1>

	<p>Simply performs an access control check to see if various roles are allowed to access this page.</p> 

	<% 
		String user = request.getParameter( "user" );
		if ( user != null ) {
			System.out.println( "Authenticating as " + user );
			request.logout();
			request.login(user,"test");
		}
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Switch User:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="accessD.jsp" autocomplete="off">
						<button name="user" type="submit" value="UserA" class="btn btn-warning">UserA</button>
						<button name="user" type="submit" value="UserB" class="btn btn-warning">UserB</button>
						<button name="user" type="submit" value="UserC" class="btn btn-warning">UserC</button>
						<button name="user" type="submit" value="UserD" class="btn btn-warning">UserD</button>
						<button name="user" type="submit" value="UserE" class="btn btn-warning">UserE</button>
					</form>
				</div>
			</div>
		</div>
	</div>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Access Allowed?</h3>
				</div>
				<div class="panel-body">
				</div>
			</div>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>
