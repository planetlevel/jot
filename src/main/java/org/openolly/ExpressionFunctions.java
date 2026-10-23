package org.openolly;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import org.openolly.log.FluentLogger;

/**
 * Functions a JOT can call from an expression, like #matches(#P0.cookies, "token"). Every public static method here is registered
 * by Expression under its own name. They are what a drafted JOT is given in place of T( and new, which the dashboard doesn't allow
 * there. The functions take any kind of value, so one call covers a String, an array, a Collection or an Enumeration, which is what
 * servlet and library methods hand back, and they never fail on a null.
 *
 * An expression runs on every call of the method it watches, and the text it is given can come from whoever is sending the request, so
 * a pattern here is compiled once and kept, is only tried on the start of a long text, and gives up after a short time. A pattern that
 * gives up counts as not matching, and the agent log says so.
 */
public final class ExpressionFunctions {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();

	/** Text longer than this is tested on its first characters. */
	static final int MAX_TEXT = 8192;
	/** How long one pattern may take on one text before it is given up on. */
	static final long BUDGET_NANOS = 50_000_000L;
	private static final int MAX_PATTERNS = 256;
	/** a card number is 13 to 19 digits, with spaces or dashes between groups */
	private static final int MIN_CARD = 13, MAX_CARD = 19, MAX_CARD_TEXT = 32;

	// what kind() looks for. A social security number, nine digits with the dashes optional. A web token, three parts with dots between,
	// the last one possibly empty for an unsigned one. A token is 32 or more letters, digits, underscores and dashes, which is what a session
	// id, an api key or a hash looks like. No two of these can describe the same text, a card is at most 32 characters with its spaces and
	// has no letters, and a token has no dots.
	private static final Pattern SSN = Pattern.compile( "^\\d{3}-?\\d{2}-?\\d{4}$" );
	private static final Pattern JWT = Pattern.compile( "^eyJ[\\w-]+\\.[\\w-]+\\.[\\w-]*$" );
	private static final Pattern TOKEN = Pattern.compile( "^[A-Za-z0-9_\\-]{32,}$" );

	private static final Map<String, Pattern> patterns = new ConcurrentHashMap<String, Pattern>();
	private static final AtomicLong lastWarning = new AtomicLong();

	private ExpressionFunctions() {
	}

	/**
	 * The value as a list. An array, a Collection, an Iterable or an Enumeration becomes a list of its items, anything else is a list of
	 * one, and null is an empty list. A null item is left out. A list of cookies can then be read with .?[...] and .![name] like any other.
	 */
	public static List<Object> list(Object value) {
		List<Object> out = new ArrayList<Object>();
		if ( value == null ) return out;
		if ( value instanceof Object[] items ) {
			for ( Object item : items ) if ( item != null ) out.add( item );
		} else if ( value.getClass().isArray() ) {
			int length = Array.getLength( value );
			for ( int i = 0; i < length; i++ ) out.add( Array.get( value, i ) );
		} else if ( value instanceof Iterable<?> items ) {
			for ( Object item : items ) if ( item != null ) out.add( item );
		} else if ( value instanceof Enumeration<?> items ) {
			for ( Object item : Collections.list( items ) ) if ( item != null ) out.add( item );
		} else if ( value instanceof Iterator<?> items ) {
			while ( items.hasNext() ) {
				Object item = items.next();
				if ( item != null ) out.add( item );
			}
		} else {
			out.add( value );
		}
		return out;
	}

	/**
	 * True when the text of the value, or of any item of it, has a match for the regular expression anywhere in it, which is how the
	 * matchers of a JOT work, so ^ and $ are written to anchor it. (?i) makes it case insensitive.
	 */
	public static boolean matches(Object value, String regex) {
		Pattern pattern = compile( regex );
		for ( Object item : list( value ) ) {
			if ( find( pattern, text( item ) ) ) return true;
		}
		return false;
	}

	/** The items of the value whose text has a match for the regular expression, as they are, so a cookie stays a cookie. */
	public static List<Object> matching(Object value, String regex) {
		Pattern pattern = compile( regex );
		List<Object> out = new ArrayList<Object>();
		for ( Object item : list( value ) ) {
			if ( find( pattern, text( item ) ) ) out.add( item );
		}
		return out;
	}

	/**
	 * True when the value, or any item of it, is a card number. That is 13 to 19 digits, which may have spaces or dashes between them,
	 * and no other text, and the last digit has to be the right check digit. A regular expression can't check that, and it is what
	 * tells a card number from an order number of the same length.
	 */
	public static boolean luhn(Object value) {
		for ( Object item : list( value ) ) {
			if ( isCard( text( item ) ) ) return true;
		}
		return false;
	}

	/**
	 * What kind of sensitive value the value is, or null when it is none. It is ssn for a social security number, card for a card number
	 * that passes the check of luhn, jwt for a web token and token for a long run of letters and digits like a session id or an api key.
	 * For an array or a collection it is the kind of the first item that has one, and a text longer than the limit on text is none of
	 * them. The patterns are kept here, so a JOT says what it wants to
	 * know and not how to find it, and they get the same limits on time and length as every other function.
	 */
	public static String kind(Object value) {
		for ( Object item : list( value ) ) {
			String text = item instanceof CharSequence ? item.toString() : String.valueOf( item );
			// none of these is that long, and the start of a longer text, tested as if it were all of it, can look like a token when it is not
			if ( text.length() > MAX_TEXT ) continue;
			if ( find( SSN, text ) ) return "ssn";
			if ( isCard( text ) ) return "card";
			if ( find( JWT, text ) ) return "jwt";
			if ( find( TOKEN, text ) ) return "token";
		}
		return null;
	}

	/** The names of the functions, which are what an expression can call as #name(...). */
	public static List<String> names() {
		List<String> out = new ArrayList<String>();
		for ( java.lang.reflect.Method m : ExpressionFunctions.class.getDeclaredMethods() ) {
			if ( isFunction( m ) && !out.contains( m.getName() ) ) out.add( m.getName() );
		}
		Collections.sort( out );
		return out;
	}

	static boolean isFunction(java.lang.reflect.Method m) {
		int modifiers = m.getModifiers();
		return java.lang.reflect.Modifier.isPublic( modifiers ) && java.lang.reflect.Modifier.isStatic( modifiers ) && !m.getName().equals( "names" );
	}

	// ------------------------------------------------------------------ the parts

	private static String text(Object item) {
		String text = item instanceof CharSequence ? item.toString() : String.valueOf( item );
		return text.length() > MAX_TEXT ? text.substring( 0, MAX_TEXT ) : text;
	}

	private static Pattern compile(String regex) {
		if ( regex == null ) throw new IllegalArgumentException( "a pattern is needed" );
		Pattern found = patterns.get( regex );
		if ( found == null ) {
			found = Pattern.compile( regex );
			// the patterns come from the JOT files, so there are only ever a few, but one built from the data would never stop
			if ( patterns.size() >= MAX_PATTERNS ) patterns.clear();
			patterns.put( regex, found );
		}
		return found;
	}

	private static boolean find(Pattern pattern, String text) {
		try {
			return pattern.matcher( new Deadline( text, System.nanoTime() + BUDGET_NANOS ) ).find();
		} catch ( TooSlow e ) {
			long now = System.currentTimeMillis();
			long last = lastWarning.get();
			// a request someone made to hurt the application could make this happen on every call, which would fill the log
			if ( now - last > 10_000 && lastWarning.compareAndSet( last, now ) ) {
				logger.atWarning().log( "[JOT] The pattern %s took too long on a text of %d characters, so it counts as no match", pattern.pattern(), text.length() );
			}
			return false;
		}
	}

	private static boolean isCard(String text) {
		if ( text.length() > MAX_CARD_TEXT ) return false;
		int digits = 0, sum = 0;
		boolean second = false, same = true;
		char first = 0;
		for ( int i = text.length() - 1; i >= 0; i-- ) {
			char c = text.charAt( i );
			if ( c == ' ' || c == '-' ) continue;
			if ( c < '0' || c > '9' ) return false;
			int d = c - '0';
			if ( second ) {
				d *= 2;
				if ( d > 9 ) d -= 9;
			}
			sum += d;
			second = !second;
			if ( digits == 0 ) first = c;
			else if ( c != first ) same = false;
			digits++;
		}
		// one digit repeated, like a column of zeros, passes the check but is not a card
		return digits >= MIN_CARD && digits <= MAX_CARD && sum % 10 == 0 && !same;
	}

	/** Thrown from inside a regular expression that has used up its time. It carries no stack, since it is a way out and not a fault. */
	private static final class TooSlow extends RuntimeException {
		private static final long serialVersionUID = 1L;

		TooSlow() {
			super( null, null, false, false );
		}
	}

	/**
	 * The text, which looks at the clock now and then as the pattern reads it. A pattern that backtracks without end still reads the
	 * text again and again, so this is the one place a program can step in.
	 */
	private static final class Deadline implements CharSequence {
		private final CharSequence text;
		private final long deadline;
		private int reads;

		Deadline(CharSequence text, long deadline) {
			this.text = text;
			this.deadline = deadline;
		}

		public int length() {
			return text.length();
		}

		public char charAt(int index) {
			if ( ( ++reads & 1023 ) == 0 && System.nanoTime() > deadline ) throw new TooSlow();
			return text.charAt( index );
		}

		public CharSequence subSequence(int start, int end) {
			return new Deadline( text.subSequence( start, end ), deadline );
		}

		public String toString() {
			return text.toString();
		}
	}
}
