package com.acme.ticketbook.idor;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * The data accessors for the IDOR exercise. Each lookup comes in two forms. The plain one fetches whatever the id names, which is the
 * flaw. The "For" one adds the owner to the query, which is the fix. Every method takes the acting user, as an audit context would,
 * so a sensor on these methods can see the id, who asked, and (from the result) whose record it was.
 */
public class IdorStore {

	private static final String URL = "jdbc:hsqldb:mem:ticketdb";
	public static final String[] USERS = { "UserA", "UserB", "UserC", "UserD", "UserE" };
	private static final String COLUMNS = "id, ticket_no, ref, owner, subject, body, status";

	static {
		try {
			Class.forName("org.hsqldb.jdbcDriver");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		reset();
	}

	private static Connection open() throws SQLException {
		return DriverManager.getConnection(URL, "sa", "");
	}

	/** Drops and seeds the tables again, two bookings for each user. */
	public static synchronized void reset() {
		try (Connection c = open(); Statement st = c.createStatement()) {
			st.executeUpdate("DROP TABLE idor_docs IF EXISTS");
			st.executeUpdate("DROP TABLE idor_outbox IF EXISTS");
			seedAccess(c);
			st.executeUpdate("CREATE TABLE idor_docs (id INTEGER PRIMARY KEY, ticket_no VARCHAR(12), ref VARCHAR(16), owner VARCHAR(32), "
					+ "subject VARCHAR(128), body VARCHAR(512), status VARCHAR(16))");
			st.executeUpdate("CREATE TABLE idor_outbox (id INTEGER IDENTITY, sent_to VARCHAR(128), sent_by VARCHAR(32), "
					+ "subject VARCHAR(128), body VARCHAR(512))");
			String[] places = { "Washington DC", "Baltimore", "Philadelphia", "Denver", "Boston", "Chicago", "Austin", "Seattle", "Miami", "Portland" };
			try (PreparedStatement ps = c.prepareStatement("INSERT INTO idor_docs VALUES (?,?,?,?,?,?,?)")) {
				for (int i = 0; i < 10; i++) {
					int id = 1001 + i;
					String owner = USERS[i % USERS.length];
					ps.setInt(1, id);
					ps.setString(2, "2025" + String.format("%04d", id));
					ps.setString(3, "TB-" + id);
					ps.setString(4, owner);
					ps.setString(5, "Booking to " + places[i]);
					ps.setString(6, "Passenger " + owner + ", seat " + (10 + i) + "A, card ending 4" + (200 + i) + ", confirmation C" + (7000 + i * 13));
					ps.setString(7, "OPEN");
					ps.executeUpdate();
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	/** One opaque access id for each user, made once and kept when the bookings are reset, so a signed-in session's context stays good. */
	private static void seedAccess(Connection c) throws SQLException {
		try (Statement st = c.createStatement()) {
			st.executeUpdate("CREATE TABLE idor_access (user_id VARCHAR(32) PRIMARY KEY, access_id VARCHAR(32))");
		} catch (SQLException e) {
			return;   // it is already there
		}
		java.security.SecureRandom random = new java.security.SecureRandom();
		try (PreparedStatement ps = c.prepareStatement("INSERT INTO idor_access VALUES (?,?)")) {
			for (String user : USERS) {
				byte[] b = new byte[8];
				random.nextBytes(b);
				StringBuilder sb = new StringBuilder("AC-");
				for (byte x : b) {
					sb.append(String.format("%02x", x));
				}
				ps.setString(1, user);
				ps.setString(2, sb.toString());
				ps.executeUpdate();
			}
		}
	}

	/** The context for a user who has just signed in, or null for a user the exercise doesn't know. */
	public synchronized SecurityContext contextFor(String user) {
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement("SELECT access_id FROM idor_access WHERE user_id = ?")) {
			ps.setString(1, user);
			try (ResultSet rs = ps.executeQuery()) {
				return rs.next() ? new SecurityContext(user, rs.getString(1)) : null;
			}
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
		}
	}

	private static Doc row(ResultSet rs) throws SQLException {
		return new Doc(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7));
	}

	private static synchronized Doc find(String column, Object value, String owner) {
		return find(column, value, owner, null);
	}

	private static synchronized Doc find(String column, Object value, String owner, String access) {
		String sql = "SELECT " + COLUMNS + " FROM idor_docs WHERE " + column + " = ? AND status <> 'DELETED'" + (owner == null ? "" : " AND owner = ?")
				+ (access == null ? "" : " AND owner IN (SELECT user_id FROM idor_access WHERE access_id = ?)");
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setObject(1, value);
			int next = 2;
			if (owner != null) {
				ps.setString(next++, owner);
			}
			if (access != null) {
				ps.setString(next, access);
			}
			try (ResultSet rs = ps.executeQuery()) {
				return rs.next() ? row(rs) : null;
			}
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
		}
	}

	// *** the flaw, the record the id names, whoever is asking ***
	public Doc byId(int id, String actor) { return find("id", id, null); }
	public Doc byNumber(String number, String actor) { return find("ticket_no", number, null); }
	public Doc byRef(String ref, String actor) { return find("ref", ref, null); }

	// *** the fix, only a record the actor owns ***
	public Doc byIdFor(int id, String actor) { return find("id", id, actor); }
	public Doc byNumberFor(String number, String actor) { return find("ticket_no", number, actor); }
	public Doc byRefFor(String ref, String actor) { return find("ref", ref, actor); }

	// *** the fix again, from the SecurityContext in the session, not from the request or the signed-in name ***
	// reading and updating check the user id
	public Doc byIdIn(int id, SecurityContext ctx) { return ctx == null ? null : find("id", id, ctx.getUserId()); }
	public Doc byNumberIn(String number, SecurityContext ctx) { return ctx == null ? null : find("ticket_no", number, ctx.getUserId()); }
	public Doc byRefIn(String ref, SecurityContext ctx) { return ctx == null ? null : find("ref", ref, ctx.getUserId()); }
	// changing or sending a record checks the access id
	public Doc byIdAccess(int id, SecurityContext ctx) { return ctx == null ? null : find("id", id, null, ctx.getAccessId()); }
	public Doc byNumberAccess(String number, SecurityContext ctx) { return ctx == null ? null : find("ticket_no", number, null, ctx.getAccessId()); }
	public Doc byRefAccess(String ref, SecurityContext ctx) { return ctx == null ? null : find("ref", ref, null, ctx.getAccessId()); }

	/** What a user's own list shows. */
	public synchronized List<Doc> mine(String actor) {
		List<Doc> list = new ArrayList<>();
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement("SELECT " + COLUMNS + " FROM idor_docs WHERE owner = ? ORDER BY id")) {
			ps.setString(1, actor);
			try (ResultSet rs = ps.executeQuery()) {
				while (rs.next()) {
					list.add(row(rs));
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return list;
	}

	/** Every record, for the instructor view. */
	public synchronized List<Doc> all() {
		List<Doc> list = new ArrayList<>();
		try (Connection c = open(); Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT " + COLUMNS + " FROM idor_docs ORDER BY id")) {
			while (rs.next()) {
				list.add(row(rs));
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return list;
	}

	public synchronized void setStatus(int id, String status, String actor) {
		update("UPDATE idor_docs SET status = ? WHERE id = ?", status, id);
	}

	public synchronized void append(int id, String text, String actor) {
		update("UPDATE idor_docs SET body = SUBSTRING(body || ' | ' || ? FROM 1 FOR 512) WHERE id = ?", text, id);
	}

	/** Sends a copy of the record to an address. The mail is a row in the outbox table, which outbox.jsp shows. */
	public synchronized void mail(Doc d, String to, String actor) {
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement("INSERT INTO idor_outbox (sent_to, sent_by, subject, body) VALUES (?,?,?,?)")) {
			ps.setString(1, to);
			ps.setString(2, actor);
			ps.setString(3, d.subject + " (" + d.ref + ")");
			ps.setString(4, d.body);
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public synchronized List<String[]> outbox() {
		List<String[]> list = new ArrayList<>();
		try (Connection c = open(); Statement st = c.createStatement();
				ResultSet rs = st.executeQuery("SELECT id, sent_to, sent_by, subject, body FROM idor_outbox ORDER BY id")) {
			while (rs.next()) {
				list.add(new String[] { rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5) });
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return list;
	}

	private void update(String sql, String text, int id) {
		try (Connection c = open(); PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setString(1, text);
			ps.setInt(2, id);
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public static String esc(String s) {
		return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
	}
}
