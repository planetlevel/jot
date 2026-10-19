<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
<title>Exercise TicketBook</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<link href="/ticketbook/css/bootstrap.min.css" rel="stylesheet">
<link href="/ticketbook/css/ticketbook.css" rel="stylesheet">
</head>

<body>
<%@ include file="/menu.jsp" %>
<H1>Exercise</H1>
<p class="lead">Visits every page of TicketBook from this browser, so the sensors have something to see. It sends ordinary values,
and the attack values only if you tick the box.</p>
<p>
	<button id="run" class="btn btn-primary">Exercise all pages</button>
	<label style="margin-left:16px"><input type="checkbox" id="attacks"> include attack values</label>
	<label style="margin-left:16px">rounds <input type="number" id="rounds" value="1" min="1" max="50" style="width:4em"></label>
	<span id="summary" style="margin-left:16px"></span>
</p>
<table class="table table-condensed" id="results">
	<thead><tr><th>Page</th><th>Values sent</th><th>Status</th><th>ms</th></tr></thead>
	<tbody></tbody>
</table>
<%@ include file="/footer.jsp" %>

<script>
(function () {
	var base = "/ticketbook/";
	var D = "$";     // a dollar and brace written together would be read by JSP as its own expression, so they are joined at run time
	// get, or post with a form body. Nothing here is harmful unless it is in attack
	var pages = [
		{ page: "index.jsp" }, { page: "list.jsp" }, { page: "architecture.jsp" },
		{ page: "profile", post: { name: "Test User", city: "Columbia", cc: "4111111111111111" } },
		{ page: "check.jsp", post: { ticket: "T-1001" } },
		{ page: "request.jsp" }, { page: "response.jsp" }, { page: "roles.jsp" }, { page: "template.jsp", post: { name: "jeff" } },
		{ page: "headers.jsp", post: { cc: "on", csp: "on", sts: "on", xfo: "on", xct: "on" } },
		{ page: "includes.jsp?name=jeff" }, { page: "hello.jsp?name=jeff" },
		{ page: "log4shell.jsp", post: { input: "hello" }, attack: { input: D + "{jndi:ldap://127.0.0.1:1/a}" } },
		{ page: "jackson.jsp", post: { input: "{\"name\":\"x\"}" } },
		{ page: "snakeyaml.jsp", post: { input: "name: x" } },
		{ page: "spring4shell.jsp", post: { input: "name=x" } },
		{ page: "commonstext.jsp", post: { input: "hello" }, attack: { input: D + "{script:javascript:1+1}" } },
		{ page: "el.jsp", post: { input: "hello" }, attack: { input: D + "{1+1}" } },
		{ page: "xss.jsp?q=hello", attack: { q: "<scr" + "ipt>alert(1)</scr" + "ipt>" } },
		{ page: "cookiexss.jsp", post: { name: "color", value: "blue" } },
		{ page: "xxe.jsp" },
		{ page: "cmd.jsp", post: { cmd: "date" }, attack: { cmd: "id" } },
		{ page: "path.jsp", post: { file: "hello.jsp" }, attack: { file: "../../../../etc/passwd" } },
		{ page: "file.jsp" }, { page: "socket.jsp" },
		{ page: "ssrf.jsp", post: { urlparam: "http://127.0.0.1:1/" } },
		{ page: "classpath.jsp" },
		{ page: "hpp.jsp", post: { user: "jeff", pass1: "a", pass2: "a" } },
		{ page: "forward.jsp", post: { page: "index.jsp" } },
		{ page: "redirect.jsp", post: { url: "/ticketbook/index.jsp" } },
		{ page: "flow.jsp", post: { name: "jeff" } },
		{ page: "hash.jsp", post: { data: "hello" } },
		{ page: "accessA.jsp", post: { user: "UserA" } }, { page: "accessB.jsp", post: { user: "UserB" } },
		{ page: "accessC.jsp", post: { user: "UserC" } }, { page: "accessD.jsp", post: { user: "UserD" } },
		{ page: "accessE.jsp", post: { user: "UserE" } }
	];

	function body(values) {
		return Object.keys(values).map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(values[k]); }).join("&");
	}
	function cell(text) { var td = document.createElement("td"); td.textContent = text; return td; }

	async function visit(p, attacks, tbody) {
		var values = p.post ? Object.assign({}, p.post, attacks && p.attack ? p.attack : {}) : null;
		var url = base + p.page;
		if (!values && attacks && p.attack) url = base + p.page.split("?")[0] + "?" + body(p.attack);
		var row = document.createElement("tr");
		var sent = values ? body(values) : (url.indexOf("?") >= 0 ? url.split("?")[1] : "");
		row.append(cell(p.page.split("?")[0]), cell(sent), cell("..."), cell(""));
		tbody.append(row);
		var t = Date.now(), status;
		try {
			var r = await fetch(url, values ? { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body(values), redirect: "manual" }
				: { redirect: "manual" });
			status = r.type === "opaqueredirect" ? "redirect" : String(r.status);
			row.className = r.ok || r.type === "opaqueredirect" ? "" : "danger";
		} catch (e) { status = "failed"; row.className = "danger"; }
		row.children[2].textContent = status;
		row.children[3].textContent = String(Date.now() - t);
		return status;
	}

	document.getElementById("run").onclick = async function () {
		var button = this, tbody = document.querySelector("#results tbody"), summary = document.getElementById("summary");
		var attacks = document.getElementById("attacks").checked, rounds = Math.max(1, parseInt(document.getElementById("rounds").value, 10) || 1);
		button.disabled = true; tbody.textContent = "";
		var ok = 0, bad = 0;
		for (var round = 1; round <= rounds; round++) {
			for (var i = 0; i < pages.length; i++) {
				summary.textContent = "round " + round + " of " + rounds + ", page " + (i + 1) + " of " + pages.length;
				var s = await visit(pages[i], attacks, tbody);
				if (s === "200" || s === "redirect") ok++; else bad++;
			}
		}
		summary.textContent = "done, " + ok + " pages answered and " + bad + " did not";
		button.disabled = false;
	};
})();
</script>
</body>

</html>
