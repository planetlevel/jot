<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Register with TicketBook</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Register with TicketBook</H1>

	<%
		Ticket ticket = (Ticket)request.getAttribute( ProfileController.TICKET );
			if ( ticket != null ) {
	%>
		<div class="row">
			<div class="col-md-12">
				<div class="panel panel-primary">
					<div class="panel-heading">
						<h3 class="panel-title">New User Information</h3>
					</div>
					<div class="panel-body">
					<%
						String name = ticket.getName();
						String first = ticket.getName().split(" ")[0];
						String city = ticket.getCity();

					    out.print( "Hello "+ name +"!  Thank you for registering with TicketBook! " +
						"We have your full name " + ESAPI.encoder().encodeForHTML(name) +
					    	" and hope that you are ready to have a great time in " + ESAPI.encoder().encodeForHTML(city) +
					    	". We have encrypted your credit card information as \""+
					    	ESAPI.encoder().encodeForHTML(ticket.getCreditCard() )+"\" for your protection. " +
					    	"If you need any help, please send email to help@ticketbook.com. Thanks!" );
					%>
					
					<!--
					<iframe id="weather" style="overflow: hidden; border: none" width="475" height="140"
							src=<%="http://www.weather-forecast.com/locations/"+city+"/forecasts/latest/threedayfree"%>
							frameborder="0" marginwidth="0" marginheight="0"></iframe>
					-->
					<a href="http://www.weather-forecast.com/locations/<%=city%>/forecasts/latest/threedayfree">Get Weather</a>
					</div>
				</div>
			</div>
		</div>
	<% } %>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">New User Information</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="profile">
						<div class="form-group">
							<label for="name">Full Name:</label>
							<input name="name" id="name" class="form-control" placeholder="Enter Name" />
							<label for="city">City Name:</label>
							<input name="city" id="city" class="form-control" placeholder="Enter City" />
							<label for="cc">Credit Card:</label>
							<input name="cc" id="cc" class="form-control" placeholder="Enter Credit Card" />
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