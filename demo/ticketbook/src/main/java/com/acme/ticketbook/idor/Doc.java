package com.acme.ticketbook.idor;

/** A booking that belongs to one user. It has three ids, which the levels of the IDOR exercise use in different ways. */
public class Doc {

	public final int id;
	public final String number;
	public final String ref;
	public final String owner;
	public final String subject;
	public final String body;
	public final String status;

	public Doc(int id, String number, String ref, String owner, String subject, String body, String status) {
		this.id = id;
		this.number = number;
		this.ref = ref;
		this.owner = owner;
		this.subject = subject;
		this.body = body;
		this.status = status;
	}

	public String toJson() {
		return "{\"id\":" + id + ",\"number\":\"" + esc(number) + "\",\"ref\":\"" + esc(ref) + "\",\"owner\":\"" + esc(owner)
				+ "\",\"subject\":\"" + esc(subject) + "\",\"body\":\"" + esc(body) + "\",\"status\":\"" + esc(status) + "\"}";
	}

	private static String esc(String s) {
		return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
	}
}
