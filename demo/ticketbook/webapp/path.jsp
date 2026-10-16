<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.net.URLEncoder"%>
<%@ page import="java.io.*"%>
<%@ page import="nu.xom.Builder"%>
<%@ page import="nu.xom.Document"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Path Injection</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>Path Injection</H1>

	<p>Path Injection (aka Path Traversal) happens <span class="text-danger">every</span> time untrusted data is used in a file path. The attacker can use file
	system meta-characters like . .. / \ ~ ; %00 and others to manipulate the path and access or overwrite existing files.
	Try ../../../../../../../../../../../../../etc/passwd.

	<div>Enter filename:</div>
	<BR>
	<form method="POST" action="path.jsp" autocomplete="off">
		<input name='file' value='constitution.txt'>
		<input type='submit' name='submit' value='Go!'>
	</form>

	<%
		String param = request.getParameter("file");
		String path = request.getSession().getServletContext().getRealPath("") + "/" + param;
		
		String content = "No content found";
		if (param != null) {
				BufferedReader reader = new BufferedReader(new FileReader( path ));

				String line = null;
				StringBuilder stringBuilder = new StringBuilder();
				String ls = System.getProperty("line.separator");

				while ((line = reader.readLine()) != null) {
					stringBuilder.append(line);
					stringBuilder.append(ls);
				}

				content = stringBuilder.toString();
		}
	%>

	<BR>
	<BR>

	<div>File Content:</div>
	<BR>
	<textarea cols='80' rows='25'>
	<%=content%>
	</textarea>

	<%@ include file="/footer.jsp"%>
</body>

</html>