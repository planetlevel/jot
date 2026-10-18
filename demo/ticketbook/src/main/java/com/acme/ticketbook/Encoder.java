package com.acme.ticketbook;

public class Encoder {

	public static String encode( String s ) {
		StringBuilder sb = new StringBuilder();
		for ( int i=0; i<s.length(); i++ ) {
			char c = s.charAt(i);
			if ( Character.isLetterOrDigit( c ) ) {
				sb.append( c );
			} else {
				sb.append( '.' );
			}
		}
		return sb.toString();
	}
}
