package com.acme.ticketbook;

import java.util.regex.Pattern;

public class Validator {

	private static Pattern p = Pattern.compile( "[A-Za-z0-9] " );

	public static boolean isValid( String s ) {
		return p.matcher(s).matches();
	}
	
}
