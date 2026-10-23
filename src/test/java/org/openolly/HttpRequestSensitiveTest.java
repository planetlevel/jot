package org.openolly;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * The four sensitive request sensors of the ticketbook demo, run the way the agent runs them. A parameter and a cookie are each looked at
 * twice, once for a name that says it holds something sensitive and once for a value that is sensitive, and the two are kept apart. They
 * are read out of the demo's own jot file, so what is tested is what is saved there, and they are called with stand-ins for the servlet
 * request and its cookies.
 *
 * A sensor records nothing when a list it captures is empty, which is how these stay quiet for a request with nothing to report, and it
 * records null for a field whose expression fails. So a test that expects a name to be reported also proves the expression runs, and a
 * test that expects nothing checks that no event was made.
 */
class HttpRequestSensitiveTest {

	static final String PARAMETER_NAME = "http-parameter-sensitive-name";
	static final String PARAMETER_VALUE = "http-parameter-sensitive-value";
	static final String COOKIE_NAME = "http-cookie-sensitive-name";
	static final String COOKIE_VALUE = "http-cookie-sensitive-value";
	static final String SOURCE = "demo/ticketbook/.jot/jot.yaml";
	static final String FIELD = "names";
	static final String KINDS = "kinds";

	// the parts of a servlet request that the sensors read. A SpEL property is read with the getter, so these are enough
	public static class FakeCookie {
		private final String name;
		private final String value;

		public FakeCookie(String name, String value) {
			this.name = name;
			this.value = value;
		}

		public String getName() {
			return name;
		}

		public String getValue() {
			return value;
		}
	}

	public static class FakeRequest {
		private final Map<String, String[]> parameters = new LinkedHashMap<String, String[]>();
		private final List<FakeCookie> cookies = new ArrayList<FakeCookie>();
		private boolean noCookies = true;

		public FakeRequest param(String name, String... values) {
			parameters.put( name, values );
			return this;
		}

		public FakeRequest cookie(String name, String value) {
			cookies.add( new FakeCookie( name, value ) );
			noCookies = false;
			return this;
		}

		public Map<String, String[]> getParameterMap() {
			return parameters;
		}

		// a servlet container returns null, not an empty array, when the request has no cookies
		public FakeCookie[] getCookies() {
			return noCookies ? null : cookies.toArray( new FakeCookie[0] );
		}
	}

	static Sensor parameterName;
	static Sensor parameterValue;
	static Sensor cookieName;
	static Sensor cookieValue;
	static List<String> problems;

	@BeforeAll
	static void loadTheSavedSensors() throws Exception {
		ObjectMapper mapper = new ObjectMapper( new YAMLFactory() );
		JsonNode all = mapper.readTree( new File( SOURCE ) );
		List<JsonNode> saved = new ArrayList<JsonNode>();
		for ( String name : List.of( PARAMETER_NAME, PARAMETER_VALUE, COOKIE_NAME, COOKIE_VALUE ) ) {
			JsonNode found = null;
			for ( JsonNode candidate : all.get( "sensors" ) ) {
				if ( name.equals( candidate.get( "name" ).asText() ) ) found = candidate;
			}
			Assertions.assertNotNull( found, name + " is not in " + SOURCE );
			// under a name of its own, since the sensors of every test share one registry and the first definition of a name wins
			ObjectNode copy = found.deepCopy();
			copy.put( "name", "request-test-" + name );
			saved.add( copy );
		}
		// only these are loaded, so the others in the file don't leave anything behind for the other tests
		Path only = Files.createTempDirectory( "sensitive" ).resolve( "only.jot" );
		Files.writeString( only, mapper.writeValueAsString( Map.of( "sensors", saved ) ) );
		ConfigReader.load( only.toFile() );
		// the problems are the agent's for everything loaded so far, and other tests load files that are wrong on purpose
		problems = new ArrayList<String>( ConfigReader.getProblems().stream().filter( p -> p.contains( only.getFileName().toString() ) ).toList() );
		parameterName = find( "request-test-" + PARAMETER_NAME );
		parameterValue = find( "request-test-" + PARAMETER_VALUE );
		cookieName = find( "request-test-" + COOKIE_NAME );
		cookieValue = find( "request-test-" + COOKIE_VALUE );
		AppScope.configure( List.of() );
		PlatformWork.configure( null );
	}

	private static Sensor find(String name) {
		return Sensor.getSensors().stream().filter( s -> name.equals( s.getName() ) ).findFirst().orElse( null );
	}

	@AfterAll
	static void noApplicationScopeLeftBehind() {
		AppScope.configure( List.of() );
		PlatformWork.configure( null );
	}

	@BeforeEach
	void noScope() {
		AppScope.configure( List.of() );
	}

	@AfterEach
	void stopTheBus() {
		EventBus.shutdown();
	}

	/** The events a sensor records for one request. */
	private List<Event> fire(Sensor sensor, FakeRequest request) {
		List<Event> out = new ArrayList<Event>();
		EventBus.configure( List.of( (EventSink) out::add ), 100 );
		sensor.execute( "t", "sig", null, new Object[] { request }, null );
		EventBus.shutdown();
		return out;
	}

	private Event reportedBy(Sensor sensor, FakeRequest request) {
		List<Event> events = fire( sensor, request );
		Assertions.assertEquals( 1, events.size(), sensor + " has one event for a request with something to report" );
		Assertions.assertEquals( sensor.getName(), events.get( 0 ).getRule() );
		return events.get( 0 );
	}

	@SuppressWarnings("unchecked")
	private List<String> list(Sensor sensor, FakeRequest request, String field) {
		Object value = reportedBy( sensor, request ).getData().get( field );
		Assertions.assertTrue( value instanceof List, field + " is a list, and not text or null, which means the expression ran, it was " + value );
		return (List<String>) value;
	}

	private List<String> parameterNames(FakeRequest request) {
		return list( parameterName, request, FIELD );
	}

	private List<String> parameterValues(FakeRequest request) {
		return list( parameterValue, request, FIELD );
	}

	private List<String> parameterKinds(FakeRequest request) {
		return list( parameterValue, request, KINDS );
	}

	private List<String> cookieNames(FakeRequest request) {
		return list( cookieName, request, FIELD );
	}

	private List<String> cookieValues(FakeRequest request) {
		return list( cookieValue, request, FIELD );
	}

	private List<String> cookieKinds(FakeRequest request) {
		return list( cookieValue, request, KINDS );
	}

	private void assertQuiet(Sensor sensor, FakeRequest request, String why) {
		Assertions.assertEquals( 0, fire( sensor, request ).size(), sensor + " " + why );
	}

	private void assertAllQuiet(FakeRequest request, String why) {
		for ( Sensor sensor : List.of( parameterName, parameterValue, cookieName, cookieValue ) ) assertQuiet( sensor, request, why );
	}

	// the number with the check digit that makes it a card number
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

	// ------------------------------------------------------------------ the sensors as saved

	@Test
	void theSavedSensorsLoadWithoutProblemsAndWatchTheServletOnBothApis() {
		Map<Sensor, List<String>> fields = new LinkedHashMap<Sensor, List<String>>();
		fields.put( parameterName, List.of( FIELD ) );
		fields.put( parameterValue, List.of( FIELD, KINDS ) );
		fields.put( cookieName, List.of( FIELD ) );
		fields.put( cookieValue, List.of( FIELD, KINDS ) );
		Assertions.assertTrue( problems.isEmpty(), "the agent found problems with them, " + problems );
		for ( Map.Entry<Sensor, List<String>> entry : fields.entrySet() ) {
			Sensor sensor = entry.getKey();
			Assertions.assertNotNull( sensor, "a sensor was not loaded" );
			List<String> watched = sensor.getMethods().stream().map( Object::toString ).toList();
			Assertions.assertTrue( watched.stream().anyMatch( m -> m.contains( "javax.servlet.Servlet" ) && m.contains( "service" ) ), sensor + " javax, " + watched );
			Assertions.assertTrue( watched.stream().anyMatch( m -> m.contains( "jakarta.servlet.Servlet" ) && m.contains( "service" ) ), sensor + " jakarta, " + watched );
			Assertions.assertEquals( entry.getValue(), new ArrayList<String>( sensor.getCaptures().keySet() ), sensor + " records " + entry.getValue() );
			Assertions.assertNull( sensor.getBlockWhen(), sensor + " only records, a sensor that looks at every request must not be able to stop one" );
		}
	}

	// ------------------------------------------------------------------ parameters by name

	@Test
	void aParameterWhoseNameSaysItIsSecretIsReportedByName() {
		for ( String name : List.of( "password", "PASSWORD", "Password", "passwd", "user_password", "token", "access_token", "csrfToken",
			"secret", "client_secret", "apikey", "api_key", "apiKey", "API_KEY", "ssn", "SSN", "ssn_last4", "card", "card_number", "cardNumber",
			"cardno", "credit_card", "creditcard" ) ) {
			FakeRequest request = new FakeRequest().param( name, "x" );
			Assertions.assertEquals( List.of( name ), parameterNames( request ), "the name " + name + " says it is sensitive" );
			assertQuiet( parameterValue, request, "and the value x is not, so it is only the name" );
		}
	}

	@Test
	void aHeaderStyleNameWithADashIsReportedToo() {
		for ( String name : List.of( "api-key", "x-api-key", "access-token", "client-secret", "credit-card" ) ) {
			Assertions.assertEquals( List.of( name ), parameterNames( new FakeRequest().param( name, "x" ) ), name );
		}
	}

	@Test
	void aParameterWithAnOrdinaryNameAndValueIsNotReported() {
		FakeRequest request = new FakeRequest().param( "name", "Bob" ).param( "page", "2" ).param( "q", "hello world" ).param( "id", "42" )
			.param( "sort", "asc" ).param( "email", "bob@example.com" );
		assertAllQuiet( request, "nothing in it is sensitive, so there is nothing to record" );
	}

	@Test
	void aNameThatMerelyContainsTheLettersOfAWordIsNotReported() {
		for ( String name : List.of( "classname", "businessname", "discard", "scorecard", "cardinal", "assn", "username" ) ) {
			assertAllQuiet( new FakeRequest().param( name, "x" ), "the name " + name + " is not about a secret" );
		}
	}

	@Test
	void theNamesAreReportedInTheOrderTheyCameAndOnlyTheSensitiveOnes() {
		FakeRequest request = new FakeRequest().param( "user", "bob" ).param( "password", "hunter2" ).param( "page", "1" ).param( "api_key", "k" );
		Assertions.assertEquals( List.of( "password", "api_key" ), parameterNames( request ) );
	}

	@Test
	void aSensitiveNameIsFoundNextToOrdinaryOnes() {
		// the first version lost the whole answer as soon as one parameter had an ordinary name, which is nearly every request
		Assertions.assertEquals( List.of( "password" ), parameterNames( new FakeRequest().param( "username", "bob" ).param( "password", "x" ) ) );
		Assertions.assertEquals( List.of( "password" ), parameterNames( new FakeRequest().param( "password", "x" ).param( "username", "bob" ) ) );
	}

	@Test
	void aParameterWithNoValuesIsStillReportedForItsName() {
		Assertions.assertEquals( List.of( "password" ), parameterNames( new FakeRequest().param( "q" ).param( "password" ) ) );
		assertAllQuiet( new FakeRequest().param( "q" ), "a parameter with no values has nothing to look at" );
	}

	// ------------------------------------------------------------------ parameters by value

	@Test
	void aSocialSecurityNumberIsReportedByValueWhateverTheParameterIsCalled() {
		for ( String value : List.of( "123-45-6789", "123456789", "123-456789", "12345-6789" ) ) {
			FakeRequest request = new FakeRequest().param( "q", value );
			Assertions.assertEquals( List.of( "q" ), parameterValues( request ), value );
			Assertions.assertEquals( List.of( "ssn" ), parameterKinds( request ), value );
			assertQuiet( parameterName, request, "the name q is ordinary, it is the value" );
		}
	}

	@Test
	void aCreditCardNumberIsReportedByValueInTheWaysItIsWritten() {
		for ( String value : List.of( "4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111", "378282246310005", "3782 822463 10005",
			"4222222222222", "6799990100000000019", "5555555555554444" ) ) {
			FakeRequest request = new FakeRequest().param( "q", value );
			Assertions.assertEquals( List.of( "q" ), parameterValues( request ), value );
			Assertions.assertEquals( List.of( "card" ), parameterKinds( request ), value );
		}
	}

	@Test
	void anOrderNumberAsLongAsACardIsNotACard() {
		for ( String value : List.of( "4111111111111112", "1234567890123456", "9999999999999", "0000000000000000", "4111 1111 1111 1112" ) ) {
			assertAllQuiet( new FakeRequest().param( "order", value ), value + " fails the check digit, or is one digit repeated" );
		}
	}

	@Test
	void theNumberOfDigitsDecidesWhetherItCouldBeACard() {
		assertAllQuiet( new FakeRequest().param( "q", withCheckDigit( "41111111111" ) ), "12 digits" );
		for ( String body : List.of( "411111111111", "411111111111111", "411111111111111111" ) ) {
			Assertions.assertEquals( List.of( "card" ), parameterKinds( new FakeRequest().param( "q", withCheckDigit( body ) ) ), body.length() + 1 + " digits" );
		}
		assertAllQuiet( new FakeRequest().param( "q", withCheckDigit( "4111111111111111111" ) ), "20 digits" );
	}

	@Test
	void aWebTokenIsReportedByValueAsAJwt() {
		String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
		Assertions.assertEquals( List.of( "jwt" ), parameterKinds( new FakeRequest().param( "q", jwt ) ) );
		Assertions.assertEquals( List.of( "jwt" ), parameterKinds( new FakeRequest().param( "q", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0." ) ), "an unsigned one has an empty last part" );
	}

	@Test
	void aLongRandomLookingValueIsReportedByValueAsAToken() {
		String token32 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
		Assertions.assertEquals( 32, token32.length() );
		Assertions.assertEquals( List.of( "token" ), parameterKinds( new FakeRequest().param( "q", token32 ) ) );
		Assertions.assertEquals( List.of( "token" ), parameterKinds( new FakeRequest().param( "q", "AbC_dEf-123".repeat( 6 ) ) ), "url safe base64 uses _ and -" );
		assertAllQuiet( new FakeRequest().param( "q", token32.substring( 1 ) ), "31 characters is not long enough" );
	}

	@Test
	void thingsThatLookALittleLikeSecretsButAreNotAreLeftAlone() {
		FakeRequest request = new FakeRequest()
			.param( "phone", "555-123-4567" )
			.param( "date", "2026-10-20" )
			.param( "zip", "90210" )
			.param( "path", "/ticketbook/profile.jsp" )
			.param( "sentence", "the quick brown fox jumps over the lazy dog again and again" )
			.param( "version", "1.2.3" )
			.param( "amount", "1234.56" );
		assertAllQuiet( request, "none of these is sensitive" );
	}

	@Test
	void theKindsLineUpWithTheNamesOneForOne() {
		FakeRequest request = new FakeRequest().param( "q", "123-45-6789" ).param( "page", "1" ).param( "n", "4111 1111 1111 1111" )
			.param( "t", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" ).param( "j", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0." );
		Assertions.assertEquals( List.of( "q", "n", "t", "j" ), parameterValues( request ) );
		Assertions.assertEquals( List.of( "ssn", "card", "token", "jwt" ), parameterKinds( request ), "the kind of each name, in the same order" );
	}

	@Test
	void aParameterWithSeveralValuesIsReportedWhenAnyOfThemIsSensitiveAndTheKindIsTheFirstFound() {
		FakeRequest request = new FakeRequest().param( "q", "fine", "4111111111111111", "123-45-6789", "also fine" );
		Assertions.assertEquals( List.of( "q" ), parameterValues( request ) );
		Assertions.assertEquals( List.of( "card" ), parameterKinds( request ) );
		assertAllQuiet( new FakeRequest().param( "q", "fine", "also fine" ), "none of the values is" );
	}

	@Test
	void aMissingValueInsideAParameterDoesNotStopTheRest() {
		Assertions.assertEquals( List.of( "q" ), parameterValues( new FakeRequest().param( "q", null, "123-45-6789" ) ) );
		Assertions.assertEquals( List.of( "password" ), parameterNames( new FakeRequest().param( "q", (String) null ).param( "password", "x" ) ) );
		assertAllQuiet( new FakeRequest().param( "q", (String) null ), "a missing value is not a secret" );
	}

	// ------------------------------------------------------------------ parameters both ways

	@Test
	void aParameterThatIsSensitiveByNameAndByValueIsReportedByBothAndEachSaysWhy() {
		FakeRequest request = new FakeRequest().param( "card", "4111111111111111" ).param( "page", "1" );
		Assertions.assertEquals( List.of( "card" ), parameterNames( request ), "the name says it" );
		Assertions.assertEquals( List.of( "card" ), parameterValues( request ), "and so does the value" );
		Assertions.assertEquals( List.of( "card" ), parameterKinds( request ) );
	}

	@Test
	void eachWayOnlyReportsWhatItFound() {
		FakeRequest request = new FakeRequest().param( "password", "hunter2" ).param( "note", "123-45-6789" ).param( "page", "1" );
		Assertions.assertEquals( List.of( "password" ), parameterNames( request ), "by name, a field called password" );
		Assertions.assertEquals( List.of( "note" ), parameterValues( request ), "by value, an SSN in a field called note" );
		Assertions.assertEquals( List.of( "ssn" ), parameterKinds( request ) );
	}

	// ------------------------------------------------------------------ cookies by name

	@Test
	void aCookieNamedForSomethingItShouldNeverHoldIsReportedByName() {
		for ( String name : List.of( "password", "Password", "passwd", "user_password", "secret", "app_secret", "client-secret", "ssn", "SSN", "ssn_last4",
			"card", "card_number", "cardnumber", "cardNo", "credit_card", "creditcard" ) ) {
			FakeRequest request = new FakeRequest().cookie( name, "x" );
			Assertions.assertEquals( List.of( name ), cookieNames( request ), "the cookie " + name );
			assertQuiet( cookieValue, request, "and its value x is not sensitive" );
		}
	}

	@Test
	void aSessionOrTokenCookieIsNotReportedBecauseEveryRequestHasOne() {
		String token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
		String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
		for ( String name : List.of( "JSESSIONID", "sessionid", "session", "PHPSESSID", "sess_id", "WEBWOLFSESSION", "auth_token", "csrf_token", "XSRF-TOKEN",
			"remember_token", "api_key", "access_token" ) ) {
			for ( String value : List.of( token, jwt ) ) {
				assertQuiet( cookieName, new FakeRequest().cookie( name, value ), "the cookie " + name + " is where a token belongs" );
				assertQuiet( cookieValue, new FakeRequest().cookie( name, value ), "and so is a value like " + value.substring( 0, 8 ) );
			}
		}
	}

	@Test
	void anOrdinaryBrowserRequestWithItsSessionCookiesIsQuiet() {
		// what nearly every request of an application looks like, which is what made the first version record all of them
		FakeRequest request = new FakeRequest().param( "page", "2" )
			.cookie( "ticketbook42", "ticketbook" + "x".repeat( 300 ) )
			.cookie( "JSESSIONID", "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6" ).cookie( "JSESSIONID", "9F8E7D6C5B4A39281716059483726150" )
			.cookie( "WEBWOLFSESSION", "0123456789abcdef0123456789abcdef" ).cookie( "theme", "dark" );
		assertAllQuiet( request, "every cookie and the parameter are meant to be there" );
	}

	@Test
	void aCookieWithAnOrdinaryNameAndValueIsNotReported() {
		FakeRequest request = new FakeRequest().cookie( "theme", "dark" ).cookie( "lang", "en" ).cookie( "tz", "America/New_York" ).cookie( "count", "3" );
		assertAllQuiet( request, "nothing in it is sensitive" );
	}

	@Test
	void theCookiesAreReportedInTheOrderTheyCameAndOnlyTheSensitiveOnes() {
		FakeRequest request = new FakeRequest().cookie( "theme", "dark" ).cookie( "password", "x" ).cookie( "lang", "en" ).cookie( "ssn", "y" ).cookie( "JSESSIONID", "z" );
		Assertions.assertEquals( List.of( "password", "ssn" ), cookieNames( request ) );
	}

	@Test
	void aCookieWithNoValueIsFine() {
		Assertions.assertEquals( List.of( "password" ), cookieNames( new FakeRequest().cookie( "password", null ) ), "the name alone is enough" );
		assertAllQuiet( new FakeRequest().cookie( "theme", null ), "an ordinary name with no value" );
		assertAllQuiet( new FakeRequest().cookie( "JSESSIONID", null ), "a session cookie is not reported even with nothing in it" );
	}

	@Test
	void aRequestWithNoCookiesAtAllIsQuietForTheCookiesAndTheParametersStillCount() {
		FakeRequest request = new FakeRequest().param( "password", "x" );
		Assertions.assertNull( request.getCookies(), "a container gives null, which the sensor has to cope with" );
		assertQuiet( cookieName, request, "no cookies" );
		assertQuiet( cookieValue, request, "no cookies" );
		Assertions.assertEquals( List.of( "password" ), parameterNames( request ) );
	}

	// ------------------------------------------------------------------ cookies by value

	@Test
	void aCookieHoldingAnSsnOrACardNumberIsReportedByValueWhateverItIsCalled() {
		Assertions.assertEquals( List.of( "a" ), cookieValues( new FakeRequest().cookie( "a", "123-45-6789" ) ), "SSN" );
		Assertions.assertEquals( List.of( "ssn" ), cookieKinds( new FakeRequest().cookie( "a", "123-45-6789" ) ) );
		Assertions.assertEquals( List.of( "ssn" ), cookieKinds( new FakeRequest().cookie( "a", "123456789" ) ), "SSN without dashes" );
		Assertions.assertEquals( List.of( "card" ), cookieKinds( new FakeRequest().cookie( "b", "4111 1111 1111 1111" ) ), "card" );
		Assertions.assertEquals( List.of( "card" ), cookieKinds( new FakeRequest().cookie( "b", "378282246310005" ) ), "an Amex" );
		assertAllQuiet( new FakeRequest().cookie( "e", "4111111111111112" ), "a number that fails the card check" );
		assertAllQuiet( new FakeRequest().cookie( "e", "0000000000000000" ), "a number that is one digit repeated" );
	}

	@Test
	void aCookieValueThatIsATokenOrAWebTokenIsNotReportedByValue() {
		assertAllQuiet( new FakeRequest().cookie( "d", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" ), "a long token" );
		assertAllQuiet( new FakeRequest().cookie( "c", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0." ), "a web token" );
	}

	@Test
	void aCookieThatIsSensitiveByNameAndByValueIsReportedByBothAndTheKindLinesUp() {
		FakeRequest request = new FakeRequest().cookie( "theme", "dark" ).cookie( "ssn", "123-45-6789" ).cookie( "x", "4111111111111111" ).cookie( "password", "hunter2" );
		Assertions.assertEquals( List.of( "ssn", "password" ), cookieNames( request ), "by name" );
		Assertions.assertEquals( List.of( "ssn", "x" ), cookieValues( request ), "by value" );
		Assertions.assertEquals( List.of( "ssn", "card" ), cookieKinds( request ), "one kind for each name found by value" );
	}

	// ------------------------------------------------------------------ the sensors beside each other

	@Test
	void aRequestWithOnlyAParameterOrOnlyACookieStillGetsItsEvent() {
		// a list with nothing in it records nothing, so one sensor with both lists only spoke when both had something to say
		FakeRequest parameter = new FakeRequest().param( "card", "4111111111111111" ).cookie( "theme", "dark" );
		Assertions.assertEquals( List.of( "card" ), parameterNames( parameter ) );
		assertQuiet( cookieName, parameter, "nothing is said about the cookies" );
		assertQuiet( cookieValue, parameter, "or their values" );
		FakeRequest cookie = new FakeRequest().cookie( "password", "x" );
		Assertions.assertEquals( List.of( "password" ), cookieNames( cookie ) );
		assertQuiet( parameterName, cookie, "nothing is said about the parameters" );
		assertQuiet( parameterValue, cookie, "or their values" );
	}

	@Test
	void aRequestWithNothingSensitiveIsNotRecordedByAnySensor() {
		assertAllQuiet( new FakeRequest().param( "page", "1" ).param( "sort", "asc" ).cookie( "theme", "dark" ), "every page of the application is a request, so nothing to say must mean no event" );
		assertAllQuiet( new FakeRequest(), "no parameters and no cookies" );
	}

	// ------------------------------------------------------------------ what the events say

	@Test
	void theEventsNameWhatWasFoundAndNeverWhatItHeld() {
		String ssn = "123-45-6789";
		String card = "4111 1111 1111 1111";
		String token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
		String jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.";
		String password = "correct horse battery staple";
		FakeRequest request = new FakeRequest().param( "password", password ).param( "q", ssn ).param( "n", card ).param( "t", token ).param( "j", jwt )
			.cookie( "secret", token ).cookie( "x", ssn ).cookie( "JSESSIONID", token );
		List<Event> events = new ArrayList<Event>();
		for ( Sensor sensor : List.of( parameterName, parameterValue, cookieName, cookieValue ) ) events.addAll( fire( sensor, request ) );
		Assertions.assertEquals( 4, events.size(), "each sensor has something to say" );
		StringBuilder everything = new StringBuilder();
		for ( Event e : events ) everything.append( e.getCapture() ).append( ' ' ).append( e.getData() ).append( ' ' ).append( e );
		for ( String secret : List.of( ssn, card, token, jwt, password, "4111", "6789", "correct horse", "a1b2c3d4" ) ) {
			Assertions.assertFalse( everything.toString().contains( secret ), "an event must not hold " + secret + ", they are " + everything );
		}
		Assertions.assertTrue( everything.toString().contains( "password" ) && everything.toString().contains( "secret" ), "but they do say which ones, " + everything );
		Assertions.assertEquals( List.of( "password" ), events.get( 0 ).getData().get( FIELD ), "by name, only the field called password" );
		Assertions.assertEquals( List.of( "q", "n", "t", "j" ), events.get( 1 ).getData().get( FIELD ), "by value" );
		Assertions.assertEquals( List.of( "ssn", "card", "token", "jwt" ), events.get( 1 ).getData().get( KINDS ), "and what each one was" );
		Assertions.assertEquals( List.of( "secret" ), events.get( 2 ).getData().get( FIELD ), "the cookie called secret, and not the session cookie" );
		Assertions.assertEquals( List.of( "x" ), events.get( 3 ).getData().get( FIELD ), "the cookie holding the SSN, and not the ones holding a token" );
		Assertions.assertEquals( List.of( "ssn" ), events.get( 3 ).getData().get( KINDS ) );
	}

	@Test
	void theFieldsAreListsSoTheyCanBeReadAndFilteredOneByOne() {
		FakeRequest request = new FakeRequest().param( "password", "x" ).param( "q", "123-45-6789" ).cookie( "ssn", "4111111111111111" );
		Assertions.assertTrue( reportedBy( parameterName, request ).getData().get( FIELD ) instanceof List );
		Assertions.assertTrue( reportedBy( parameterValue, request ).getData().get( KINDS ) instanceof List );
		Assertions.assertEquals( List.of( FIELD, KINDS ), new ArrayList<String>( reportedBy( parameterValue, request ).getData().keySet() ), "named, in the order the JOT lists them" );
		Assertions.assertEquals( parameterValues( request ).size(), parameterKinds( request ).size() );
	}

	@Test
	void manyRequestsInARowEachGetTheirOwnAnswer() {
		// nothing is kept from one request to the next
		Assertions.assertEquals( List.of( "password" ), parameterNames( new FakeRequest().param( "password", "x" ) ) );
		assertAllQuiet( new FakeRequest().param( "page", "1" ), "an ordinary one in between" );
		Assertions.assertEquals( List.of( "ssn" ), parameterKinds( new FakeRequest().param( "q", "123-45-6789" ) ) );
		Assertions.assertEquals( List.of( "card" ), parameterKinds( new FakeRequest().param( "q", "4111111111111111" ) ), "not the kind of the one before" );
		Assertions.assertEquals( List.of( "password" ), cookieNames( new FakeRequest().cookie( "password", "x" ) ) );
		assertAllQuiet( new FakeRequest().cookie( "theme", "dark" ), "and for the cookies" );
	}

	@Test
	void aLargeRequestIsHandled() {
		FakeRequest request = new FakeRequest();
		for ( int i = 0; i < 500; i++ ) request.param( "field" + i, "value " + i );
		request.param( "client_secret", "x" );
		request.param( "q", "123-45-6789" );
		for ( int i = 0; i < 100; i++ ) request.cookie( "c" + i, "v" + i );
		Assertions.assertEquals( List.of( "client_secret" ), parameterNames( request ) );
		Assertions.assertEquals( List.of( "q" ), parameterValues( request ) );
		assertQuiet( cookieName, request, "none of the hundred cookies is sensitive" );
		assertQuiet( cookieValue, request, "and none of their values" );
	}

	@Test
	void aHugeValueSomeoneSentToSlowTheApplicationDownIsHandledQuickly() {
		FakeRequest request = new FakeRequest().param( "q", "a ".repeat( 500_000 ) ).param( "r", "(a+)+".repeat( 20_000 ) ).param( "s", "a".repeat( 1_000_000 ) )
			.cookie( "c", "a - ".repeat( 250_000 ) );
		long start = System.nanoTime();
		assertAllQuiet( request, "a megabyte of text with nothing sensitive in it is not a token, and a megabyte of letters is not one either" );
		long ms = ( System.nanoTime() - start ) / 1_000_000;
		Assertions.assertTrue( ms < 3000, "it is looked at in part and not for as long as it is, took " + ms + " ms" );
	}
}
