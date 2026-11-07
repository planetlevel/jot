package com.acme.ticketbook.idor;

import java.io.Serializable;

/**
 * Who the session belongs to, kept in the session when the user signs in. The user id says whose records the user may read and
 * update, the access id is an opaque token issued to that user, which the actions that change or send something check. Neither one
 * comes from the request, so the ids a request carries can be anything and the check still holds.
 */
public class SecurityContext implements Serializable {

	private static final long serialVersionUID = 1L;

	private final String userId;
	private final String accessId;

	public SecurityContext(String userId, String accessId) {
		this.userId = userId;
		this.accessId = accessId;
	}

	public String getUserId() {
		return userId;
	}

	public String getAccessId() {
		return accessId;
	}
}
