<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Ticket Inventory</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Ticket Inventory</H1>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Ticket Number</h3>
				</div>
				<div class="panel-body">
					<table class="table table-hover">
						<%
							for ( Ticket t : Database.getInstance().getTickets() ) {
								out.println( "<tr><td>"+t.getTicket()+"</td><td><a href=\"check.jsp?ticket="+t.getTicket()+"\">"+t.getName()+"</a></td><td>"+t.getCity()+"</td></tr>");
							}
						%>
					</table>
				</div>
			</div>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>