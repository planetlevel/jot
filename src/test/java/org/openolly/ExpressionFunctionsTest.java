package org.openolly;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.PatternSyntaxException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ExpressionFunctionsTest {

	public static class Cookie {
		private final String name;
		private final String value;

		public Cookie(String name, String value) {
			this.name = name;
			this.value = value;
		}

		public String getName() {
			return name;
		}

		public String getValue() {
			return value;
		}

		public String toString() {
			return name + "=" + value;
		}
	}

	private static Object eval(String expression, Object... params) {
		try {
			return new Expression( expression ).execute( null, params, null, null, null );
		} catch ( NoSuchMethodException e ) {
			throw new IllegalStateException( e );
		}
	}

	// the card number with the check digit that makes it pass
	private static String withCheckDigit(String body) {
		for ( int check = 0; check < 10; check++ ) {
			String candidate = body + check;
			int sum = 0;
			boolean second = false;
			for ( int i = candidate.length() - 1; i >= 0; i-- ) {
				int d = candidate.charAt( i ) - '0';
				if ( second ) {
					d *= 2;
					if ( d > 9 ) d -= 9;
				}
				sum += d;
				second = !second;
			}
			if ( sum % 10 == 0 ) return candidate;
		}
		throw new IllegalStateException();
	}

	// ------------------------------------------------------------------ list

	@Test
	void listTurnsWhatEverKindOfCollectionIntoAList() {
		Assertions.assertEquals( List.of( "a", "b" ), ExpressionFunctions.list( new String[] { "a", "b" } ), "an array" );
		Assertions.assertEquals( List.of( "a", "b" ), ExpressionFunctions.list( List.of( "a", "b" ) ), "a list" );
		Assertions.assertEquals( List.of( "a", "b" ), ExpressionFunctions.list( new LinkedHashSet<String>( List.of( "a", "b" ) ) ), "a set" );
		Assertions.assertEquals( List.of( "a", "b" ), ExpressionFunctions.list( new Vector<String>( List.of( "a", "b" ) ).elements() ), "an Enumeration" );
		Assertions.assertEquals( List.of( "a", "b" ), ExpressionFunctions.list( List.of( "a", "b" ).iterator() ), "an Iterator" );
		Assertions.assertEquals( List.of( 1, 2, 3 ), ExpressionFunctions.list( new int[] { 1, 2, 3 } ), "an array of numbers" );
	}

	@Test
	void listOfOneThingIsThatThingAndOfNothingIsEmpty() {
		Assertions.assertEquals( List.of( "a" ), ExpressionFunctions.list( "a" ) );
		Assertions.assertEquals( List.of(), ExpressionFunctions.list( null ), "what a container gives for no cookies" );
		Assertions.assertEquals( List.of(), ExpressionFunctions.list( new String[0] ) );
		Map<String, String> map = Map.of( "k", "v" );
		Assertions.assertEquals( List.of( map ), ExpressionFunctions.list( map ), "a map is one thing" );
	}

	@Test
	void listLeavesOutNullsAndKeepsTheItemsAsTheyAre() {
		Cookie a = new Cookie( "a", "1" );
		Cookie b = new Cookie( "b", "2" );
		List<Object> out = ExpressionFunctions.list( new Cookie[] { a, null, b } );
		Assertions.assertEquals( 2, out.size() );
		Assertions.assertSame( a, out.get( 0 ), "a cookie stays a cookie, so .![name] works on it" );
		Assertions.assertSame( b, out.get( 1 ) );
		Assertions.assertEquals( List.of( "a" ), ExpressionFunctions.list( Arrays.asList( "a", null ) ) );
	}

	@Test
	void listGivesACopyThatTheCallerMayChange() {
		List<String> original = new ArrayList<String>( List.of( "a" ) );
		List<Object> copy = ExpressionFunctions.list( original );
		copy.add( "b" );
		Assertions.assertEquals( List.of( "a" ), original );
	}

	// ------------------------------------------------------------------ matches and matching

	@Test
	void matchesLooksForTheExpressionAnywhereInTheText() {
		Assertions.assertTrue( ExpressionFunctions.matches( "my_password_field", "password" ) );
		Assertions.assertFalse( ExpressionFunctions.matches( "username", "password" ) );
		Assertions.assertFalse( ExpressionFunctions.matches( "my_password_field", "^password$" ), "^ and $ anchor it" );
		Assertions.assertTrue( ExpressionFunctions.matches( "password", "^password$" ) );
		Assertions.assertFalse( ExpressionFunctions.matches( "PASSWORD", "password" ), "case matters" );
		Assertions.assertTrue( ExpressionFunctions.matches( "PASSWORD", "(?i)password" ), "unless it is asked not to" );
	}

	@Test
	void matchesWorksOnAnythingThatHoldsText() {
		Assertions.assertTrue( ExpressionFunctions.matches( new String[] { "a", "token", "b" }, "tok" ), "an array" );
		Assertions.assertTrue( ExpressionFunctions.matches( List.of( "a", "token" ), "tok" ), "a list" );
		Assertions.assertFalse( ExpressionFunctions.matches( new String[] { "a", "b" }, "tok" ) );
		Assertions.assertTrue( ExpressionFunctions.matches( 12345, "^\\d+$" ), "a number is its digits" );
		Assertions.assertTrue( ExpressionFunctions.matches( new StringBuilder( "secret" ), "secret" ), "any text" );
	}

	@Test
	void matchesNeverFailsOnNothing() {
		Assertions.assertFalse( ExpressionFunctions.matches( null, "x" ) );
		Assertions.assertFalse( ExpressionFunctions.matches( new String[0], "x" ) );
		Assertions.assertFalse( ExpressionFunctions.matches( new String[] { null }, "x" ) );
		Assertions.assertTrue( ExpressionFunctions.matches( new String[] { null, "x" }, "x" ), "a null beside a match is skipped" );
		Assertions.assertTrue( ExpressionFunctions.matches( "", "^$" ), "an empty text is still text" );
	}

	@Test
	void aMissingOrBrokenPatternIsAnErrorTheJotAuthorCanSee() {
		Assertions.assertThrows( IllegalArgumentException.class, () -> ExpressionFunctions.matches( "x", null ) );
		Assertions.assertThrows( PatternSyntaxException.class, () -> ExpressionFunctions.matches( "x", "(" ) );
	}

	@Test
	void matchingGivesTheItemsThatMatchAsTheyAre() {
		Cookie token = new Cookie( "auth_token", "x" );
		Cookie theme = new Cookie( "theme", "dark" );
		Cookie session = new Cookie( "JSESSIONID", "y" );
		List<Object> out = ExpressionFunctions.matching( new Object[] { token, theme, session }, "(?i)token|session" );
		Assertions.assertEquals( 2, out.size(), "the text of an object is its toString" );
		Assertions.assertSame( token, out.get( 0 ), "and what comes back is the object, not its text" );
		Assertions.assertSame( session, out.get( 1 ) );
	}

	@Test
	void matchingOnTextKeepsTheOrderAndDropsTheRest() {
		Assertions.assertEquals( List.of( "password", "api_key" ), ExpressionFunctions.matching( List.of( "user", "password", "page", "api_key" ), "password|key" ) );
		Assertions.assertEquals( List.of(), ExpressionFunctions.matching( List.of( "user" ), "password" ) );
		Assertions.assertEquals( List.of(), ExpressionFunctions.matching( null, "password" ) );
	}

	@Test
	void aVeryLongTextIsTestedOnItsFirstPartOnly() {
		String filler = "x".repeat( ExpressionFunctions.MAX_TEXT );
		Assertions.assertTrue( ExpressionFunctions.matches( "token" + filler, "token" ), "a match at the start is found" );
		Assertions.assertFalse( ExpressionFunctions.matches( filler + "token", "token" ), "one past the limit is not looked at" );
	}

	// ------------------------------------------------------------------ patterns that could hurt

	@Test
	void aPatternThatBacktracksWithoutEndGivesUpAndCountsAsNoMatch() {
		String attack = "a".repeat( 60 ) + "b";
		long start = System.nanoTime();
		boolean found = ExpressionFunctions.matches( attack, "^(a+)+$" );
		long ms = ( System.nanoTime() - start ) / 1_000_000;
		Assertions.assertFalse( found );
		Assertions.assertTrue( ms < 2000, "it stopped after about 50 ms and not after the heat death of the universe, took " + ms + " ms" );
	}

	@Test
	void theSameAttackThroughEveryFunctionIsStopped() {
		String attack = "a".repeat( 60 ) + "b";
		long start = System.nanoTime();
		Assertions.assertEquals( List.of(), ExpressionFunctions.matching( List.of( attack, attack ), "^(a+)+$" ) );
		Assertions.assertFalse( ExpressionFunctions.matches( new String[] { attack, attack, attack }, "(x+x+)+y" ) );
		Assertions.assertTrue( ( System.nanoTime() - start ) / 1_000_000 < 5000 );
	}

	@Test
	void afterAPatternGaveUpTheNextOneStillWorks() {
		ExpressionFunctions.matches( "a".repeat( 60 ) + "b", "^(a+)+$" );
		Assertions.assertTrue( ExpressionFunctions.matches( "password", "pass" ) );
		Assertions.assertTrue( ExpressionFunctions.matches( "aaa", "^(a+)+$" ), "and the same pattern on a text it can handle" );
	}

	@Test
	void manyDifferentPatternsAreAllRightEvenThoughOnlySomeAreKept() {
		for ( int i = 0; i < 1000; i++ ) {
			Assertions.assertTrue( ExpressionFunctions.matches( "value" + i, "^value" + i + "$" ), "pattern " + i );
			Assertions.assertFalse( ExpressionFunctions.matches( "value" + i, "^value" + ( i + 1 ) + "$" ) );
		}
	}

	@Test
	void manyThreadsAtOnceAllGetTheRightAnswer() throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool( 8 );
		try {
			List<Future<Boolean>> results = new ArrayList<Future<Boolean>>();
			for ( int i = 0; i < 400; i++ ) {
				final int n = i;
				results.add( pool.submit( () -> {
					boolean yes = ExpressionFunctions.matches( List.of( "a", "tok" + n ), "^tok" + ( n % 7 ) + "$|tok" + n );
					boolean no = ExpressionFunctions.matches( "nothing", "tok" + n );
					boolean card = ExpressionFunctions.luhn( "4111 1111 1111 1111" );
					return yes && !no && card;
				} ) );
			}
			for ( Future<Boolean> r : results ) Assertions.assertTrue( r.get() );
		} finally {
			pool.shutdownNow();
		}
	}

	// ------------------------------------------------------------------ luhn

	@Test
	void cardNumbersThatPassTheCheckAreCards() {
		for ( String card : List.of( "4111111111111111", "5555555555554444", "378282246310005", "6011111111111117", "3530111333300000", "4222222222222", "6799990100000000019" ) ) {
			Assertions.assertTrue( ExpressionFunctions.luhn( card ), card );
		}
	}

	@Test
	void spacesAndDashesBetweenTheDigitsAreFine() {
		Assertions.assertTrue( ExpressionFunctions.luhn( "4111 1111 1111 1111" ) );
		Assertions.assertTrue( ExpressionFunctions.luhn( "4111-1111-1111-1111" ) );
		Assertions.assertTrue( ExpressionFunctions.luhn( "3782 822463 10005" ) );
	}

	@Test
	void aNumberWithTheWrongCheckDigitIsNotACard() {
		Assertions.assertFalse( ExpressionFunctions.luhn( "4111111111111112" ), "an order number as long as a card" );
		Assertions.assertFalse( ExpressionFunctions.luhn( "1234567890123" ) );
		Assertions.assertFalse( ExpressionFunctions.luhn( "41111111111111111" ), "17 digits that fail the check" );
	}

	@Test
	void theLengthDecidesEvenWhenTheCheckPasses() {
		Assertions.assertFalse( ExpressionFunctions.luhn( withCheckDigit( "41111111111" ) ), "12 digits" );
		Assertions.assertTrue( ExpressionFunctions.luhn( withCheckDigit( "411111111111" ) ), "13 digits" );
		Assertions.assertTrue( ExpressionFunctions.luhn( withCheckDigit( "411111111111111111" ) ), "19 digits" );
		Assertions.assertFalse( ExpressionFunctions.luhn( withCheckDigit( "4111111111111111111" ) ), "20 digits" );
	}

	@Test
	void textAroundTheDigitsMeansItIsNotACardNumber() {
		Assertions.assertFalse( ExpressionFunctions.luhn( "card 4111111111111111" ) );
		Assertions.assertFalse( ExpressionFunctions.luhn( "4111111111111111x" ) );
		Assertions.assertFalse( ExpressionFunctions.luhn( "4111.1111.1111.1111" ) );
		Assertions.assertFalse( ExpressionFunctions.luhn( "" ) );
		Assertions.assertFalse( ExpressionFunctions.luhn( "  " ) );
		Assertions.assertFalse( ExpressionFunctions.luhn( null ) );
	}

	@Test
	void oneRepeatedDigitIsNotACardEvenThoughItPassesTheCheck() {
		Assertions.assertFalse( ExpressionFunctions.luhn( "0000000000000" ), "a zero filled id" );
		Assertions.assertFalse( ExpressionFunctions.luhn( "0000 0000 0000 0000" ) );
		Assertions.assertTrue( ExpressionFunctions.luhn( "4000000000000002" ), "but zeros inside a card are fine" );
	}

	@Test
	void luhnLooksAtEveryItemOfACollection() {
		Assertions.assertTrue( ExpressionFunctions.luhn( new String[] { "fine", "4111111111111111" } ) );
		Assertions.assertFalse( ExpressionFunctions.luhn( new String[] { "fine", "1234" } ) );
		Assertions.assertTrue( ExpressionFunctions.luhn( 4111111111111111L ), "a number" );
	}

	@Test
	void aHugeTextIsRefusedQuickly() {
		Assertions.assertFalse( ExpressionFunctions.luhn( "4".repeat( 1_000_000 ) ) );
	}

	// ------------------------------------------------------------------ kind

	@Test
	void kindSaysWhatSortOfSensitiveValueItIs() {
		Assertions.assertEquals( "ssn", ExpressionFunctions.kind( "123-45-6789" ) );
		Assertions.assertEquals( "ssn", ExpressionFunctions.kind( "123456789" ) );
		Assertions.assertEquals( "card", ExpressionFunctions.kind( "4111 1111 1111 1111" ) );
		Assertions.assertEquals( "card", ExpressionFunctions.kind( "378282246310005" ) );
		Assertions.assertEquals( "jwt", ExpressionFunctions.kind( "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0." ), "an unsigned one" );
		Assertions.assertEquals( "jwt", ExpressionFunctions.kind( "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" ) );
		Assertions.assertEquals( "token", ExpressionFunctions.kind( "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" ) );
		Assertions.assertEquals( "token", ExpressionFunctions.kind( "AbC_dEf-123".repeat( 6 ) ) );
	}

	@Test
	void kindIsNullForAnythingElse() {
		for ( String ordinary : List.of( "hello", "", "  ", "555-123-4567", "2026-10-20", "90210", "/ticketbook/profile.jsp", "1.2.3", "1234.56",
			"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d", "4111111111111112", "0000000000000000", "the quick brown fox jumps over the lazy dog again" ) ) {
			Assertions.assertNull( ExpressionFunctions.kind( ordinary ), "'" + ordinary + "'" );
		}
		Assertions.assertNull( ExpressionFunctions.kind( null ) );
		Assertions.assertNull( ExpressionFunctions.kind( new String[0] ) );
		Assertions.assertNull( ExpressionFunctions.kind( new String[] { null } ) );
	}

	@Test
	void kindOfSomethingWithSeveralItemsIsTheFirstItemThatHasOne() {
		Assertions.assertEquals( "card", ExpressionFunctions.kind( new String[] { "fine", "4111111111111111", "123-45-6789" } ) );
		Assertions.assertEquals( "ssn", ExpressionFunctions.kind( List.of( "fine", "123-45-6789", "4111111111111111" ) ) );
		Assertions.assertNull( ExpressionFunctions.kind( List.of( "fine", "also fine" ) ) );
		Assertions.assertEquals( "ssn", ExpressionFunctions.kind( new String[] { null, "123-45-6789" } ), "a null in front is skipped" );
	}

	@Test
	void aLongNumberIsATokenAndNotACardOrAnSsn() {
		Assertions.assertEquals( "token", ExpressionFunctions.kind( "1".repeat( 32 ) ), "32 digits is not a card, which has at most 19" );
		Assertions.assertNull( ExpressionFunctions.kind( "1".repeat( 31 ) ) );
		Assertions.assertEquals( "token", ExpressionFunctions.kind( "9".repeat( 40 ) ) );
	}

	@Test
	void aTextLongerThanTheLimitIsNoKindOfSensitiveValue() {
		Assertions.assertEquals( "token", ExpressionFunctions.kind( "a".repeat( ExpressionFunctions.MAX_TEXT ) ), "up to the limit it is judged whole" );
		Assertions.assertNull( ExpressionFunctions.kind( "a".repeat( ExpressionFunctions.MAX_TEXT + 1 ) ), "a token is not that long, and its start must not stand for all of it" );
		Assertions.assertNull( ExpressionFunctions.kind( "a".repeat( ExpressionFunctions.MAX_TEXT ) + " and then some ordinary words" ) );
	}

	@Test
	void kindIsStoppedLikeTheRestWhenTheTextIsAnAttack() {
		long start = System.nanoTime();
		Assertions.assertNull( ExpressionFunctions.kind( "a ".repeat( 500_000 ) ) );
		Assertions.assertNull( ExpressionFunctions.kind( "eyJ" + "a".repeat( 100_000 ) + "." + "!".repeat( 10 ) ) );
		Assertions.assertTrue( ( System.nanoTime() - start ) / 1_000_000 < 3000 );
	}

	// ------------------------------------------------------------------ what an expression can call

	@Test
	void theFunctionsAreListedByName() {
		Assertions.assertEquals( List.of( "kind", "list", "luhn", "matches", "matching" ), ExpressionFunctions.names() );
	}

	@Test
	void everyFunctionCanBeCalledFromAnExpression() {
		Assertions.assertEquals( List.of( "a", "b" ), eval( "#list(#P0)", (Object) new String[] { "a", "b" } ) );
		Assertions.assertEquals( true, eval( "#matches(#P0, 'tok')", "my_token" ) );
		Assertions.assertEquals( List.of( "token" ), eval( "#matching(#P0, 'tok')", List.of( "a", "token" ) ) );
		Assertions.assertEquals( true, eval( "#luhn(#P0)", "4111 1111 1111 1111" ) );
		Assertions.assertEquals( "ssn", eval( "#kind(#P0)", "123-45-6789" ) );
		Assertions.assertNull( eval( "#kind(#P0)", "hello" ) );
	}

	@Test
	void anArrayOfObjectsReadsLikeAnyListOnceItIsWrapped() {
		Cookie[] cookies = { new Cookie( "theme", "dark" ), new Cookie( "auth_token", "x" ), new Cookie( "JSESSIONID", "y" ) };
		Object names = eval( "#list(#P0).?[#matches(name, '(?i)token|session')].![name]", (Object) cookies );
		Assertions.assertEquals( List.of( "auth_token", "JSESSIONID" ), names, "a real list of names, not an array and not text" );
		Assertions.assertEquals( List.of(), eval( "#list(#P0).?[#matches(name, 'nothing')].![name]", (Object) cookies ) );
		Assertions.assertEquals( List.of(), eval( "#list(#P0).?[#matches(name, 'x')].![name]", (Object) null ), "no cookies is null from a container" );
	}

	@Test
	void aMapOfStringArraysCanBeSearchedByKeyAndValue() {
		Map<String, String[]> parameters = new HashMap<String, String[]>();
		parameters.put( "q", new String[] { "fine", "123-45-6789" } );
		parameters.put( "page", new String[] { "1" } );
		parameters.put( "password", new String[] { "x" } );
		@SuppressWarnings("unchecked")
		List<String> found = (List<String>) eval( "#P0.entrySet().?[#matches(key, 'password') or #matches(value, '^\\d{3}-\\d{2}-\\d{4}$')].![key]", parameters );
		Collections.sort( found );
		Assertions.assertEquals( List.of( "password", "q" ), found );
	}

	@Test
	void toLowerLowerCasesAndToUpperUpperCases() {
		Assertions.assertEquals( "abc", eval( "#toLower(#P0)", "AbC" ), "it used to upper case, which is what toUpper is for" );
		Assertions.assertEquals( "ABC", eval( "#toUpper(#P0)", "AbC" ) );
	}

	@Test
	void anErrorInAFunctionLeavesTheExpressionNullAndTheApplicationAlone() {
		Assertions.assertNull( eval( "#matches(#P0, '(')", "x" ), "a broken pattern is logged by the agent and the result is null" );
		Assertions.assertNull( eval( "#matches(#P0, null)", "x" ) );
		Assertions.assertNull( eval( "#noSuchFunction(#P0)", "x" ), "and so is a function that isn't there" );
	}
}
