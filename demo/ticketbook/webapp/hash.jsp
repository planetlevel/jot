<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.security.*"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Weak Hash Algorithms</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Weak Hash Algorithm</H1>

	<p>Weak hash algorithms like MD5 and SHA1 are not suitable for passwords and other security uses.</p> 

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter some data</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="hash.jsp" autocomplete="off">
						<div class="form-group">
							<input name="data" id="data" value="enter data"
								class="form-control" placeholder='data'>
						</div>
						<button name="submit" type="submit" class="btn btn-warning">Submit</button>
					</form>
				</div>
			</div>
		</div>
	</div>

	<%
		String b64 = "No data";
		String data = request.getParameter( "data" );
		if ( data != null ) {
			byte[] bytesOfMessage = data.getBytes("UTF-8");
			// MessageDigest md = MessageDigest.getInstance("SHA-256");
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hash = md.digest(bytesOfMessage);
			b64 = ESAPI.encoder().encodeForBase64(hash, true );
		}
	%>

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Output</h3>
				</div>
				<div class="panel-body">
					<%=b64 %>
				</div>
			</div>
		</div>
	</div>

	<%@ include file="/footer.jsp"%>
</body>

</html>