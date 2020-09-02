package org.openolly;

import java.util.List;
import java.util.regex.Pattern;

public class Matcher {
	private Pattern pattern = null;
	private boolean negative = false;

	public Matcher( String pattern ) {
		this.pattern = Pattern.compile( pattern );
	}
	
	public Matcher( String pattern, boolean negative ) {
		this.pattern = Pattern.compile( pattern );
		this.negative = negative;
	}
	
	public boolean find( String value ) {
		return pattern.matcher(value).find();	}

	public boolean isNegative() {
		return negative;
	}

	// everything matches unless:
	//    it does not match a positive (no positives means it's a match)
	//    it does match a negative (no negatives means it's a match)
	public static boolean eval(String value, List<Matcher> positiveMatchers, List<Matcher> negativeMatchers) {
		boolean pmatch = positiveMatchers.isEmpty();
		for ( Matcher m : positiveMatchers ) {
			if ( m.find( value ) ) {
				pmatch = true;
				break;
			}
		}
		boolean nmatch = false;
		for ( Matcher m : negativeMatchers ) {
			nmatch |= m.find( value );
		}
		
		return pmatch && !nmatch;
	}
	
}
