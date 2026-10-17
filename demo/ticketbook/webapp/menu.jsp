<%
	String uri = request.getRequestURI();
	if ( !uri.endsWith( "check.jsp" ) && !uri.endsWith( "headers.jsp" ) ) {
		response.setHeader("Cache-Control","no-store, no-cache, must-revalidate"); //HTTP 1.1 controls
		response.setHeader("Pragma","no-cache"); //HTTP 1.0 controls
		response.setDateHeader ("Expires", 0); //Prevents caching on proxy servers
	}

	// the name of this page, so the sidebar can highlight it
	String menuPage = uri.substring( uri.lastIndexOf( '/' ) + 1 );
	if ( menuPage.endsWith( ".jsp" ) ) menuPage = menuPage.substring( 0, menuPage.length() - 4 );
%>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<nav class="navbar navbar-default" role="navigation">
  <div class="container-fluid">
    <div class="navbar-header">
      <a class="navbar-brand" href="/ticketbook/index.jsp">
		<img alt="Contrast Security" src="/ticketbook/img/contrast-wordmark.svg">
      </a>
	</div>
    <div class="collapse navbar-collapse">
	  <h3>TicketBook</h3>
	</div>
  </div>
</nav>

<div class="container-fluid">
	<div class="row">

		<!-- Left Side Content -->
		<div class="col-sm-2">
			<div class="well">
				<ul class="nav nav-pills nav-stacked">
<%
	// a "-" starts a group, everything else is { label, link, page name }
	String[][] menuLinks = {
		{ "-", "Application" },
		{ "Register", "/ticketbook/profile", "profile" },
		{ "List", "/ticketbook/list.jsp", "list" },
		{ "Architecture", "/ticketbook/architecture.jsp", "architecture" },
		{ "-", "Request handling" },
		{ "Check", "/ticketbook/check.jsp", "check" },
		{ "Request", "/ticketbook/request.jsp", "request" },
		{ "Response", "/ticketbook/response.jsp", "response" },
		{ "Headers", "/ticketbook/headers.jsp", "headers" },
		{ "Includes", "/ticketbook/includes.jsp?name=jeff", "includes" },
		{ "-", "CVE" },
		{ "Log4Shell", "/ticketbook/log4shell.jsp", "log4shell" },
		{ "Jackson", "/ticketbook/jackson.jsp", "jackson" },
		{ "XStream", "/ticketbook/xstream.jsp", "xstream" },
		{ "SnakeYAML", "/ticketbook/snakeyaml.jsp", "snakeyaml" },
		{ "Spring4Shell", "/ticketbook/spring4shell.jsp", "spring4shell" },
		{ "Text4Shell", "/ticketbook/commonstext.jsp", "commonstext" },
		{ "-", "Vulnerabilities" },
		{ "EL", "/ticketbook/el.jsp", "el" },
		{ "XSS", "/ticketbook/xss.jsp", "xss" },
		{ "XXE", "/ticketbook/xxe.jsp", "xxe" },
		{ "Command", "/ticketbook/cmd.jsp", "cmd" },
		{ "Path", "/ticketbook/path.jsp", "path" },
		{ "File", "/ticketbook/file.jsp", "file" },
		{ "Socket", "/ticketbook/socket.jsp", "socket" },
		{ "SSRF", "/ticketbook/ssrf.jsp", "ssrf" },
		{ "Classpath", "/ticketbook/classpath.jsp", "classpath" },
		{ "HPP", "/ticketbook/hpp.jsp", "hpp" },
		{ "Forward", "/ticketbook/forward.jsp", "forward" },
		{ "Redirect", "/ticketbook/redirect.jsp", "redirect" },
		{ "Flow", "/ticketbook/flow.jsp", "flow" },
		{ "Hash", "/ticketbook/hash.jsp", "hash" },
		{ "-", "Access control" },
		{ "Access A", "/ticketbook/accessA.jsp", "accessA" },
		{ "Access B", "/ticketbook/accessB.jsp", "accessB" },
		{ "Access C", "/ticketbook/accessC.jsp", "accessC" },
		{ "Access D", "/ticketbook/accessD.jsp", "accessD" },
		{ "Access E", "/ticketbook/accessE.jsp", "accessE" }
	};
	for ( String[] menuLink : menuLinks ) {
		if ( menuLink[0].equals( "-" ) ) {
			out.println( "<li class=\"menu-group\">" + menuLink[1] + "</li>" );
		} else {
			out.println( "<li" + ( menuPage.equals( menuLink[2] ) ? " class=\"active\"" : "" ) + "><a href=\"" + menuLink[1] + "\">" + menuLink[0] + "</a></li>" );
		}
	}
%>
				</ul>
			</div>
		</div>

		<!-- Right Side Content -->
		<div class="col-sm-10">
			<div class="well">
