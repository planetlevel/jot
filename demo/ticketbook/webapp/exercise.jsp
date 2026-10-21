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
<p class="lead">Sends requests to every page of TicketBook, as every user, in a random order, so the sensors have something to see. Each
pass takes the users in a random order and every page in a random order for each, so it covers all the pairs, and the next pass shuffles again. Most values are random,
and now and then a page gets its ordinary default. Leave this page open while it runs.</p>
<p>
	<button id="run" class="btn btn-primary">Start</button>
	<button id="stop" class="btn btn-default" disabled>Stop</button>
	<label style="margin-left:16px">minutes <input type="number" id="minutes" value="5" min="1" max="120" style="width:4em"></label>
	<label style="margin-left:16px">requests per second <input type="number" id="rate" value="3" min="1" max="20" style="width:4em"></label>
	<label style="margin-left:16px"><input type="checkbox" id="attacks"> include attack-looking values (harmless)</label>
</p>
<p id="summary"></p>
<table class="table table-condensed" id="results">
	<thead><tr><th>Page</th><th>Values sent</th><th>Status</th><th>ms</th></tr></thead>
	<tbody></tbody>
</table>
<%@ include file="/footer.jsp" %>

<script>
(function () {
	var base = "/ticketbook/";
	var D = "$";     // a dollar and brace written together would be read by JSP as its own expression, so they are joined at run time

	// values any field may get
	var common = ["", "0", "1", "-1", "42", "2147483648", "jeff", "Jeff Williams", "test@example.com", "a b c", "x".repeat(300),
		"caf\u00e9 \u2603", "%20", "null", "true", "O'Brien", "a&b=c", "../index.jsp", "/ticketbook/index.jsp", "http://127.0.0.1:1/",
		"4111111111111111", "123-45-6789", "UserA", "RoleA", "2026-10-16"];
	// Probes that look like attacks and do nothing. They read, print or fail to connect, and none writes, deletes or changes anything.
	var attackValues = ["echo hello", "date", "../../../../tmp/jot-exercise-does-not-exist", D + "{1+1}", D + "{jndi:ldap://127.0.0.1:1/a}",
		D + "{script:javascript:1+1}", "<scr" + "ipt>alert(1)</scr" + "ipt>", "' OR '1'='1", "; echo hello", "name: !!java.lang.StringBuilder [x]"];

	// get, or post with the form fields it takes. post holds the default of each field and more says what else suits it
	var pages = [
		{ page: "index.jsp" }, { page: "list.jsp" }, { page: "architecture.jsp" }, { page: "request.jsp" }, { page: "response.jsp" },
		{ page: "roles.jsp" }, { page: "xxe.jsp" },
		{ page: "xom.jsp", post: { xml: "<a>1</a>" } }, { page: "headername.jsp", query: { a: "1" } },
		{ page: "admin.jsp", post: { protocol: "http" } }, { page: "error.jsp" }, { page: "security.jsp" }, { page: "profile.jsp" },
		{ page: "include1.jsp" }, { page: "include2.jsp", query: { name: "jeff" } }, { page: "include3.jsp" }, { page: "file.jsp" }, { page: "socket.jsp" }, { page: "classpath.jsp" },
		{ page: "profile", post: { name: "Test User", city: "Columbia", cc: "4111111111111111" } },
		{ page: "check.jsp", post: { ticket: "T-1001" } },
		{ page: "template.jsp", post: { name: "jeff" } },
		{ page: "headers.jsp", post: { cc: "on", csp: "on", sts: "on", xfo: "on", xct: "on" }, flags: ["cc", "csp", "ct", "ex", "pr", "sc", "sts", "xct", "xfo", "xss"] },
		{ page: "includes.jsp", query: { name: "jeff" } }, { page: "hello.jsp", query: { name: "jeff" } },
		{ page: "xss.jsp", query: { q: "hello" } },
		{ page: "log4shell.jsp", post: { input: "hello" } },
		{ page: "jackson.jsp", post: { input: "{\"name\":\"x\"}" }, more: { input: ["{}", "[]", "{\"a\":1}", "{\"name\":null}"] } },
		{ page: "snakeyaml.jsp", post: { input: "name: x" }, more: { input: ["a: 1", "- x\n- y", "{}"] } },
		{ page: "spring4shell.jsp", post: { input: "name=x" } },
		{ page: "commonstext.jsp", post: { input: "hello" } },
		{ page: "el.jsp", post: { input: "hello" } },
		{ page: "cookiexss.jsp", post: { name: "color", value: "blue" } },
		{ page: "cmd.jsp", post: { cmd: "date" }, more: { cmd: ["date", "whoami", "pwd", "hostname"] } },
		{ page: "path.jsp", post: { file: "hello.jsp" }, more: { file: ["hello.jsp", "index.jsp", "nothing.txt", "constitution.txt"] } },
		{ page: "ssrf.jsp", post: { urlparam: "http://127.0.0.1:1/" } },
		{ page: "hpp.jsp", post: { user: "jeff", pass1: "a", pass2: "a" } },
		{ page: "forward.jsp", post: { page: "index.jsp" }, more: { page: ["index.jsp", "list.jsp", "hello.jsp", "nothing.jsp"] } },
		{ page: "redirect.jsp", post: { url: "/ticketbook/index.jsp" }, more: { url: ["/ticketbook/index.jsp", "/ticketbook/list.jsp", "http://127.0.0.1:1/"] } },
		{ page: "flow.jsp", post: { name: "jeff" } },
		{ page: "hash.jsp", post: { data: "hello" } },
		{ page: "accessA.jsp", post: { user: "UserA" }, asUser: true }, { page: "accessB.jsp", post: { user: "UserB" }, asUser: true },
		{ page: "accessC.jsp", post: { user: "UserC" }, asUser: true }, { page: "accessD.jsp", post: { user: "UserD" }, asUser: true },
		{ page: "accessE.jsp", post: { user: "UserE" }, asUser: true }
	];

	function pick(list) { return list[Math.floor(Math.random() * list.length)]; }
	function body(values) {
		return Object.keys(values).map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(values[k]); }).join("&");
	}
	function cell(text) { var td = document.createElement("td"); td.textContent = text; return td; }

	// one request, with the default values one time in five and random ones otherwise
	function choose(p, attacks) {
		// now and then a page is just opened, with no values at all, which is how a person arrives and reaches the code that
		// only runs without them. A blocked rule, like the command page's, ends a request before the rest of the page is read.
		if (p.post && Math.random() < 1 / 6) return { url: base + p.page, post: null, sent: "" };
		var useDefault = Math.random() < 0.2;
		var pool = common.concat(attacks ? attackValues : []);
		function value(name, fallback) {
			if (useDefault) return fallback;
			return pick(Math.random() < 0.5 && p.more && p.more[name] ? p.more[name] : pool);
		}
		var post = null, query = null;
		if (p.post) {
			post = {};
			Object.keys(p.post).forEach(function (k) {
				if (p.flags && !useDefault) { if (Math.random() < 0.5) post[k] = "on"; }
				else post[k] = value(k, p.post[k]);
			});
		}
		if (p.query) {
			query = {};
			Object.keys(p.query).forEach(function (k) { query[k] = value(k, p.query[k]); });
		}
		return { url: base + p.page + (query ? "?" + body(query) : ""), post: post, sent: body(post || query || {}) };
	}

	var tbody = document.querySelector("#results tbody"), summary = document.getElementById("summary");
	var timer = null, sent = 0, answered = 0, failed = 0, inFlight = 0;

	// Every page is visited as every user. A pass takes the users in a random order, and for each one all the pages in a random
	// order, then the next pass shuffles again. Switching user costs a login request, so staying with one user for a run of pages
	// covers the whole grid in about a third of the requests that switching at random would, and nothing is left out.
	var users = ["UserA", "UserB", "UserC", "UserD", "UserE", "guest"];
	var loginPages = ["accessA.jsp", "accessB.jsp", "accessC.jsp", "accessD.jsp", "accessE.jsp"];
	var deck = [], passes = 0, currentUser = null, pagesSeen = {}, usersSeen = {}, pairsSeen = {};

	function shuffle(list) {
		for (var i = list.length - 1; i > 0; i--) {
			var j = Math.floor(Math.random() * (i + 1)), t = list[i];
			list[i] = list[j]; list[j] = t;
		}
		return list;
	}
	function deal() {
		if (!deck.length) {
			shuffle(users.slice()).forEach(function (u) {
				shuffle(pages.slice()).forEach(function (p) { deck.push({ page: p, user: u }); });
			});
			deck.reverse();      // dealt from the end
			passes++;
		}
		return deck.pop();
	}

	// one request, shown in the table and counted
	async function send(label, c) {
		var row = document.createElement("tr");
		row.append(cell(label), cell(c.sent.length > 120 ? c.sent.slice(0, 120) + "..." : c.sent), cell("..."), cell(""));
		tbody.insertBefore(row, tbody.firstChild);
		while (tbody.children.length > 25) tbody.removeChild(tbody.lastChild);
		var t = Date.now(), status;
		inFlight++; sent++;
		try {
			var r = await fetch(c.url, c.post ? { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body(c.post), redirect: "manual" }
				: { redirect: "manual" });
			status = r.type === "opaqueredirect" ? "redirect" : String(r.status);
			// a page that refuses a bad value is still a page that answered
			if (r.type === "opaqueredirect" || r.status < 500) answered++; else { failed++; row.className = "danger"; }
		} catch (e) { status = "failed"; failed++; row.className = "danger"; }
		inFlight--;
		row.children[2].textContent = status;
		row.children[3].textContent = String(Date.now() - t);
	}

	async function fire(item, attacks) {
		var p = item.page;
		pagesSeen[p.page] = true; usersSeen[item.user] = true; pairsSeen[p.page + "\u0000" + item.user] = true;
		var c;
		if (p.asUser) {
			// an access page logs in as the user it is sent, which is how it is visited as that user
			currentUser = item.user;
			var post = { user: item.user };
			c = { url: base + p.page, post: post, sent: body(post) };
		} else {
			if (item.user !== currentUser) {
				currentUser = item.user;
				var login = loginPages[Math.floor(Math.random() * loginPages.length)], values = { user: item.user };
				await send(login + " (log in as " + item.user + ")", { url: base + login, post: values, sent: body(values) });
			}
			c = choose(p, attacks);
		}
		await send(p.page + " (" + item.user + ")", c);
	}

	function progress() {
		return Object.keys(pairsSeen).length + " of " + pages.length * users.length + " page and user pairs, pass " + passes;
	}

	function stop(why) {
		if (timer) timer.stop();
		timer = null;
		document.getElementById("run").disabled = false;
		document.getElementById("stop").disabled = true;
		summary.textContent = why + ", " + sent + " requests sent, " + answered + " answered and " + failed + " got an error, " + progress();
	}

	document.getElementById("run").onclick = function () {
		var minutes = Math.max(1, parseInt(document.getElementById("minutes").value, 10) || 5);
		var rate = Math.max(1, parseInt(document.getElementById("rate").value, 10) || 3);
		var attacks = document.getElementById("attacks").checked;
		var end = Date.now() + minutes * 60000;
		sent = answered = failed = passes = 0;
		deck = []; currentUser = null; pagesSeen = {}; usersSeen = {}; pairsSeen = {};
		tbody.textContent = "";
		document.getElementById("run").disabled = true;
		document.getElementById("stop").disabled = false;
		var started = Date.now(), issued = 0;
		function tick() {
			var left = end - Date.now();
			if (left <= 0) return stop("finished");
			summary.textContent = "running, " + Math.ceil(left / 1000) + " seconds left, " + sent + " requests sent, " + progress();
			// What is due by now, not one for each tick. A browser slows the timers of a tab you aren't looking at, to one a second and
			// then one a minute, so counting what should have been sent keeps the rate when the ticks come late.
			var due = Math.floor((Date.now() - started) / 1000 * rate) - issued;
			for (var i = 0; i < due && inFlight < 20; i++) { fire(deal(), attacks); issued++; }   // a slow page doesn't pile up requests without limit
			if (due > 0 && inFlight >= 20) issued += due;        // and what it couldn't take is dropped, not saved up
		}
		// A worker's timer is not slowed like the page's, so it is what keeps time, with the page's own as a fallback
		try {
			var worker = new Worker(URL.createObjectURL(new Blob(["setInterval(function () { postMessage(1); }, 100);"], { type: "text/javascript" })));
			worker.onmessage = tick;
			timer = { stop: function () { worker.terminate(); } };
		} catch (e) {
			var t = setInterval(tick, 250);
			timer = { stop: function () { clearInterval(t); } };
		}
	};
	document.getElementById("stop").onclick = function () { stop("stopped"); };
})();
</script>
</body>

</html>
