package com.acme.ticketbook.idor;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.Principal;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * The IDOR / BOLA exercise. Records are asked for at /idor/{level}/{operation}/{channel}, where the channel is where the request
 * carries the id (query, form, path, header, cookie or json). The accessors in IdorStore are the vulnerable part.
 *
 *   /idor/1/read/query?id=1001          /idor/2/close/header   X-Ticket-Id: 6001      /idor/3/mail/path/{token}
 *
 * The other routes are /idor/login, /idor/logout, /idor/settings and /idor/reset, which idor.jsp uses.
 */
public class IdorServlet extends HttpServlet {

	private static final String USER = "idor.user";
	private static final String CONTEXT = "idor.context";
	private static final String MODE = "idor.mode";
	private static final String VISIBLE = "idor.visible";
	private final IdorStore store = new IdorStore();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handle(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		handle(req, resp);
	}

	private void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String info = req.getPathInfo();
		String[] parts = info == null ? new String[0] : info.split("/");   // "", level, operation, channel, value
		String home = req.getContextPath() + "/idor.jsp";
		if (parts.length < 2) {
			resp.sendRedirect(home);
			return;
		}
		switch (parts[1]) {
		case "login":
			login(req, resp);
			resp.sendRedirect(home);
			return;
		case "logout":
			try {
				req.logout();
			} catch (ServletException e) {
				// nobody was signed in
			}
			HttpSession s = req.getSession(false);
			if (s != null) {
				s.removeAttribute(USER);
				s.removeAttribute(CONTEXT);
			}
			resp.sendRedirect(home);
			return;
		case "settings":
			HttpSession session = req.getSession(true);
			session.setAttribute(MODE, "patched".equals(req.getParameter("mode")) || "context".equals(req.getParameter("mode")) ? req.getParameter("mode") : "vulnerable");
			session.setAttribute(VISIBLE, "visible".equals(req.getParameter("feedback")));
			resp.sendRedirect(home);
			return;
		case "reset":
			IdorStore.reset();
			resp.sendRedirect(home);
			return;
		default:
			break;
		}
		if (parts.length < 4) {
			resp.sendError(404, "Use /idor/{level}/{operation}/{channel}");
			return;
		}
		action(req, resp, parts);
	}

	private void login(HttpServletRequest req, HttpServletResponse resp) throws ServletException {
		String user = req.getParameter("user");
		HttpSession session = req.getSession(true);   // a login Tomcat can cache needs the session to exist first
		try {
			req.logout();
			req.login(user, "test");
			session.setAttribute(USER, user);
			session.setAttribute(CONTEXT, store.contextFor(user));
		} catch (ServletException e) {
			session.removeAttribute(USER);
			session.removeAttribute(CONTEXT);
		}
	}

	private String actor(HttpServletRequest req) {
		Principal p = req.getUserPrincipal();
		if (p != null) {
			return p.getName();
		}
		HttpSession s = req.getSession(false);
		return s == null ? null : (String) s.getAttribute(USER);
	}

	private boolean flag(HttpServletRequest req, String name, boolean otherwise) {
		HttpSession s = req.getSession(false);
		Object v = s == null ? null : s.getAttribute(name);
		return v == null ? otherwise : (Boolean) v;
	}

	private void action(HttpServletRequest req, HttpServletResponse resp, String[] parts) throws IOException {
		resp.setContentType("text/plain;charset=UTF-8");
		String actor = actor(req);
		if (actor == null) {
			resp.sendError(401, "Sign in first, at idor.jsp");
			return;
		}
		int level;
		try {
			level = Integer.parseInt(parts[1]);
		} catch (NumberFormatException e) {
			resp.sendError(404, "No such level");
			return;
		}
		String op = parts[2];
		String channel = parts[3];
		String body = channel.equals("json") || "POST".equals(req.getMethod()) && req.getContentType() != null && req.getContentType().contains("json") ? body(req) : "";
		String raw = raw(req, channel, parts, body);

		Carriers.Target t;
		try {
			t = Carriers.resolve(level, channel, raw);
		} catch (Carriers.BadId e) {
			resp.sendError(400, e.getMessage());
			return;
		}

		HttpSession http = req.getSession(false);
		String mode = http == null || http.getAttribute(MODE) == null ? "vulnerable" : (String) http.getAttribute(MODE);
		SecurityContext ctx = http == null ? null : (SecurityContext) http.getAttribute(CONTEXT);
		boolean visible = flag(req, VISIBLE, false);
		boolean changes = !op.equals("read") && !op.equals("update");
		Doc d = lookup(t, actor, mode, ctx, changes);

		if (op.equals("read")) {
			if (d == null) {
				resp.sendError(404, "No such ticket");
			} else {
				resp.getWriter().println(d.toJson());
			}
			return;
		}
		if (!op.equals("update") && !op.equals("close") && !op.equals("delete") && !op.equals("mail")) {
			resp.sendError(404, "No such operation");
			return;
		}
		String done = "Action complete";
		if (d != null) {
			switch (op) {
			case "update":
				store.append(d.id, text(req, body, "text", "updated by " + actor), actor);
				break;
			case "close":
				store.setStatus(d.id, "CLOSED", actor);
				break;
			case "delete":
				store.setStatus(d.id, "DELETED", actor);
				break;
			default:
				store.mail(d, text(req, body, "to", actor + "@example.test"), actor);
				break;
			}
			done = visible ? op + " " + d.ref + " for " + d.owner + " done" : done;
		} else if (visible) {
			resp.sendError(404, "No such ticket");
			return;
		}
		resp.getWriter().println(done);
	}

	/** The record the id names. The mode picks the accessor, the flawed one, the one that checks the signed-in name, or the one that checks the session's SecurityContext. */
	private Doc lookup(Carriers.Target t, String actor, String mode, SecurityContext ctx, boolean changes) {
		boolean patched = mode.equals("patched");
		boolean context = mode.equals("context");
		switch (t.kind) {
		case 'I':
			int id = Integer.parseInt(t.value.trim());
			if (context) return changes ? store.byIdAccess(id, ctx) : store.byIdIn(id, ctx);
			return patched ? store.byIdFor(id, actor) : store.byId(id, actor);
		case 'N':
			if (context) return changes ? store.byNumberAccess(t.value, ctx) : store.byNumberIn(t.value, ctx);
			return patched ? store.byNumberFor(t.value, actor) : store.byNumber(t.value, actor);
		default:
			if (context) return changes ? store.byRefAccess(t.value, ctx) : store.byRefIn(t.value, ctx);
			return patched ? store.byRefFor(t.value, actor) : store.byRef(t.value, actor);
		}
	}

	private String raw(HttpServletRequest req, String channel, String[] parts, String body) {
		switch (channel) {
		case "path":
			return parts.length > 4 ? parts[4] : null;
		case "header":
			return req.getHeader("X-Ticket-Id");
		case "cookie":
			if (req.getCookies() != null) {
				for (Cookie c : req.getCookies()) {
					if (c.getName().equals("ticket")) {
						return c.getValue();
					}
				}
			}
			return null;
		case "json":
			return body;
		default:   // query and form
			return req.getParameter("id");
		}
	}

	private String text(HttpServletRequest req, String body, String name, String otherwise) {
		String v = req.getParameter(name);
		if (v == null) {
			v = Carriers.field(body, name);
		}
		return v == null || v.isEmpty() ? otherwise : v;
	}

	private String body(HttpServletRequest req) throws IOException {
		StringBuilder sb = new StringBuilder();
		BufferedReader r = req.getReader();
		String line;
		while ((line = r.readLine()) != null) {
			sb.append(line);
		}
		return sb.toString();
	}
}
