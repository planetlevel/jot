<%@ page import="com.acme.ticketbook.*"%>
<%@ page import="java.net.URLEncoder"%>
<%@ page import="java.io.*"%>
<%@ page import="java.security.*"%>
<%@ page import="java.nio.file.*"%>
<%@ page import="java.util.*"%>
<%@ page import="nu.xom.Builder"%>
<%@ page import="nu.xom.Document"%>
<%@ page import="org.owasp.esapi.*"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>File Access</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
	<%@ include file="/menu.jsp"%>
	<H1>File Access</H1>

	<%

		File dir = new File(getServletContext().getRealPath("/")).getParentFile();
		System.out.println( "WEBAPPS: " + dir.getAbsolutePath() );
		File[] files = dir.listFiles(new FilenameFilter() {
                      public boolean accept( File f, String name ) {
                            return( name.endsWith(".war"));
                      }
                });
                for ( File f: files ) {
                     byte[] b = Files.readAllBytes(f.toPath());
		     byte[] hash = MessageDigest.getInstance("SHA-256").digest(b);
                     String b64 = Base64.getEncoder().encodeToString(hash);
                     System.out.println( "    HASH of " + f.getName() + ": " + b64 );
                }

		String content = "No content found";
		File f = new File( "/etc/passwd" );
		BufferedReader reader = new BufferedReader(new FileReader( f ));

		String line = null;
		StringBuilder stringBuilder = new StringBuilder();
		String ls = System.getProperty("line.separator");

		while ((line = reader.readLine()) != null) {
			stringBuilder.append(line);
			stringBuilder.append(ls);
		}

		content = stringBuilder.toString();
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
