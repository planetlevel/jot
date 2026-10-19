<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page import="org.owasp.esapi.codecs.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<%
	String prefix = "ticketbook";
	String name = request.getParameter("name");
	String value = request.getParameter("value");
	if ( name != null && value != null ) {
		Cookie cookie = new Cookie( prefix+name, prefix+value );
		response.addCookie( cookie );
	}
	
	Cookie cookie = null;
	Cookie[] cookies = request.getCookies();
	if ( cookies != null ) {
	    for ( Cookie c : cookies ) {
	        if ( c.getName().startsWith( prefix ) ) {
	    	    cookie = c;
	        }
	    }
	}
%>

<head>
<title>Cookie Cross Site Scripting (XSS)</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Cookie Cross Site Scripting (XSS)</H1>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter some data to set a cookie</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="cookiexss.jsp" autocomplete="off">
						<div class="form-group">
							<input name="name" id="name" value="<c:out value="${param.name}"/>" class="form-control" placeholder='data'>
							<input name="value" id="value" value="<c:out value="${param.value}"/>" class="form-control" placeholder='data'>
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
					<h3 class="panel-title">Output</h3>
				</div>
				<div class="panel-body">
				<%
					if ( cookie != null ) {
						out.println( "<div>Cookie name: " + cookie.getName() +"</div>");
						out.println( "<div>Cookie value: " + cookie.getValue() +"</div>");
					}
				%>
				</div>
			</div>
		</div>
	</div>
	
	<%@ include file="/footer.jsp"%>
</body>

</html>