package com.acme.ticketbook.idor;

/** What idor.jsp shows a user, the id of one of their own bookings as each level and channel expects it back. */
public final class IdorLinks {

	private IdorLinks() {
	}

	public static String id(int level, String channel, Doc d) {
		return Carriers.encode(level, channel, d);
	}
}
