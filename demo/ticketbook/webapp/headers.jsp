<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.util.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Headers</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Headers</H1>

	<p>Choose the following security headers and then submit to the server. The server will respond with a page that has
	the selected headers set.</p> 

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter some data</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="headers.jsp" autocomplete="off">					            
							<div class="checkbox"><label><input type="checkbox" name="cc" value="">Cache-Control</label></div>
							<div class="checkbox"><label><input type="checkbox" name="csp" value="">Content-Security-Policy</label></div>
							<div class="checkbox"><label><input type="checkbox" name="ct" value="">Content-Type</label></div>
							<div class="checkbox"><label><input type="checkbox" name="ex" value="">Expires</label></div>
							<div class="checkbox"><label><input type="checkbox" name="pr" value="">Pragma</label></div>
							<div class="checkbox"><label><input type="checkbox" name="sc" value="">Set-Cookie</label></div>
							<!-- <div class="checkbox"><label><input type="checkbox" name="sts" value="">Strict-Transport-Security</label></div>  -->
							<div class="checkbox"><label><input type="checkbox" name="xct" value="">X-Content-Type-Options</label></div>
							<div class="checkbox"><label><input type="checkbox" name="xfo" value="">X-Frame-Options</label></div>
							<div class="checkbox"><label><input type="checkbox" name="xss" value="">X-Xss-Protection</label></div>
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
					<h3 class="panel-title">Headers Used</h3>
				</div>
				<div class="panel-body">
					<%
					// the parameters of the request, read once
					Map<String, String[]> params = request.getParameterMap();
					if ( params.containsKey( "cc" ) ) {
						response.setHeader( "Cache-Control","no-cache, no-store, must-revalidate");
						out.println( "<li>Cache-Control" + "=" + "no-cache, no-store, must-revalidate</li>");
					}
					if ( params.containsKey( "csp" ) ) {
						response.setHeader( "Content-Security-Policy", "default-src 'self'" );
						out.println( "<li>Content-Security-Policy" + "=" + "default-src 'self'</li>" );
					}
					if ( params.containsKey( "ct" ) ) {
						response.setHeader( "Content-Type", "text/html;charset=utf-8");
						out.println( "<li>Content-Type" + "=" + "text/html;charset=utf-8</li>");
					}
					if ( params.containsKey( "ex" ) ) {
						response.setHeader( "Expires", "-1");
						out.println( "<li>Expires" + "=" + "-1</li>");
					}
					if ( params.containsKey( "pr" ) ) {
						response.setHeader( "Pragma", "no-cache");
						out.println( "<li>Pragma" + "=" + "no-cache</li>");
					}
					if ( params.containsKey( "sc" ) ) {
						response.setHeader( "Set-Cookie", "name=value; path=/; secure; httponly");
						out.println( "<li>Set-Cookie" + "=" + "name=value; path=/; secure; httponly</li>");
					}
					// if ( params.containsKey( "sts" ) ) {
					//	response.setHeader( "Strict-Transport-Security", "max-age=0; includeSubDomains");
					//	out.println( "<li>Strict-Transport-Security" + "=" + "max-age=0; includeSubDomains</li>");
					// }
					if ( params.containsKey( "xct" ) ) {
						response.setHeader( "X-Content-Type-Options", "nosniff");
						out.println( "<li>X-Content-Type-Options" + "=" + "nosniff</li>");
					}
					if ( params.containsKey( "xfo" ) ) {
						response.setHeader( "X-Frame-Options", "deny");
						out.println( "<li>X-Frame-Options" + "=" + "deny</li>");
					}
					if ( params.containsKey( "xss" ) ) {
						response.setHeader( "X-XSS-Protection", "1; mode=block");
						out.println( "<li>X-XSS-Protection" + "=" + "1; mode=block</li>");
					}
					%>
				</div>
			</div>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>