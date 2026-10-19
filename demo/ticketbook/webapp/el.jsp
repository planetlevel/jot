<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="jakarta.el.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Expression Language Injection</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Expression Language Injection</H1>

	<P>Expression language injection happens when untrusted data is sent to an expression engine. If the attacker sends
	just the right expression, they can invoke their own code and take over your server.</P>
	<% 
		String input = request.getParameter( "input" );
		if ( input == null ) input = "Arshan";


        ExpressionFactory factory = ExpressionFactory.newInstance();
        ELContext context = new StandardELContext(factory);

        ValueExpression ve = factory.createValueExpression(
                context, input, String.class);

        String result = (String) ve.getValue(context);


	%>

	<BR>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter an expression:</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" autocomplete="off">
						<div class="form-group">
							<input id="input" name="input" value="<%=ESAPI.encoder().encodeForHTML(input) %>" class="form-control" placeholder='Enter username'>
						</div>
						<button name="submit" type="submit" class="btn btn-warning">Submit</button>
					</form>
				</div>
			</div>
		</div>
	</div>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Expression Result</h3>
				</div>
				<div class="panel-body">
					<div><%=result %></div>
				</div>
			</div>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>
