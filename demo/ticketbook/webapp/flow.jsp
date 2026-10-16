<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.util.regex.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<%
	String param = request.getParameter("name");
	if (param == null) param = "Contrast for Eclipse";
%>

<head>
<title>Data Flow</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>

	<%@ include file="/menu.jsp"%>
	<H1>Data Flow</H1>

	<p>One of the most difficult things in security is accurately tracing data flow. In this example, we show how complex it can be.</p> 

	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-primary">
				<div class="panel-heading">
					<h3 class="panel-title">Enter some data to reflect into HTML</h3>
				</div>
				<div class="panel-body">
					<form role="form" method="POST" action="flow.jsp" autocomplete="off">
						<div class="form-group">
							<input name="name" id="name" value="<c:out value="<%=param %>"/>" class="form-control" placeholder='data'>
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
					out.println( "<div>Step 1: request.getParameter()</div>");
					String a = param;
					
					out.println( "<div>Step 2: assignment</div>");
					String b = a;

					Pattern.matches( "[a-z]*", b );
						
					// out.println( "<div>Step X: validate</div>");
					// Validator.isValid( b );
						
					out.println( "<div>Step 3: make a string builder</div>"); 
					StringBuilder c = new StringBuilder( b );
						
					out.println( "<div>Step 4: append</div>");
					c.append( " rocks!" );
						
					out.println( "<div>Step 5: replace a chunk</div>");
					c.replace( 3, 8, "TRAST" );
						
					out.println( "<div>Step 6: put in session</div>");
					session.setAttribute("flow",c.toString());
						
					out.println( "<div>Step 7: get from session</div>");
					String d = (String)session.getAttribute("flow");
					
					out.println( "<div>Step 8: substring</div>");
					String e = d.substring(0,d.length()-1);
					
					out.println( "<div>Step 9: Base64 encode</div>");
					String f = java.util.Base64.getEncoder().encodeToString( e.getBytes() );
					
					out.println( "<div>Step 10: Base64 decode</div>");
					String g = new String( java.util.Base64.getDecoder().decode( f ) );
					
					out.println( "<div>Step 11: split</div>");
					String h = g.split(" ")[0];
					
					// out.println( "<div>Step 13: HTML encode</div>");
					// String i = Encoder.encode( h );

					out.println( "<div>Step 14: output</div>");
					out.println( "<div>Final value is " + h + "</div>" );
						
					Pattern.matches( "[A-Z]*", h );
					try {
						Runtime.getRuntime().exec( h );
					} catch( Exception ex ) {
						System.out.println( "Caught exception: " + ex.getMessage() );
					}
				%>
				</div>
			</div>
		</div>
	</div>


	<%@ include file="/footer.jsp"%>
</body>

</html>
