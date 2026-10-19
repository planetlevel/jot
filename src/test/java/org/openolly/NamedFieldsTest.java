package org.openolly;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;
import org.openolly.reporting.JsonSink;

class NamedFieldsTest {

	List<Event> events;

	@BeforeEach
	void setUp() {
		events = new ArrayList<Event>();
		EventBus.configure( List.of( (EventSink) events::add ), 100 );
	}

	@AfterEach
	void tearDown() {
		EventBus.shutdown();
	}

	private List<Event> seen() {
		EventBus.shutdown();
		return events;
	}

	private static List<Object> call(Sensor s, Object... params) {
		return s.execute( "t", "sig", null, params, null );
	}

	@Test
	void oneCallIsOneEventWithTheFieldsByNameAndTheirOrder() {
		Sensor s = new Sensor().name( "nf-one" ).method( "x.Y.a" ).capture( "host", "#P0" ).capture( "port", "#P1" );
		call( s, "db.local", 5432 );
		List<Event> out = seen();
		Assertions.assertEquals( 1, out.size() );
		Map<String, Object> data = out.get( 0 ).getData();
		Assertions.assertEquals( List.of( "host", "port" ), new ArrayList<String>( data.keySet() ) );
		Assertions.assertEquals( "db.local", data.get( "host" ) );
		Assertions.assertEquals( 5432, data.get( "port" ), "a number stays a number" );
		Assertions.assertEquals( "host=db.local, port=5432", out.get( 0 ).getCapture() );
	}

	@Test
	void aSingleFieldIsTheCaptureAlone() {
		Sensor s = new Sensor().name( "nf-single" ).method( "x.Y.b" ).capture( "path", "#P0" );
		call( s, "/a" );
		Assertions.assertEquals( "/a", seen().get( 0 ).getCapture() );
	}

	@Test
	void aMatcherChecksItsOwnFieldOnly() {
		Sensor s = new Sensor().name( "nf-match" ).method( "x.Y.c" ).capture( "name", "#P0" ).capture( "value", "#P1" )
			.matcher( "name", "^id$" ).matcher( "value", "!null" );
		call( s, "id", "7" );
		call( s, "other", "7" );
		call( s, "id", "null" );
		List<Event> out = seen();
		Assertions.assertEquals( 1, out.size(), "both fields have to pass" );
		Assertions.assertEquals( "7", out.get( 0 ).getData().get( "value" ) );
	}

	@Test
	void aListFieldKeepsTheItemsThatMatch() {
		Sensor s = new Sensor().name( "nf-list" ).method( "x.Y.d" ).capture( "names", "#P0" ).matcher( "names", "^a" );
		call( s, List.of( "ab", "b", "ac" ) );
		call( s, List.of( "x", "y" ) );
		List<Event> out = seen();
		Assertions.assertEquals( 1, out.size(), "no item matched the second call" );
		Assertions.assertEquals( List.of( "ab", "ac" ), out.get( 0 ).getData().get( "names" ) );
	}

	@Test
	void theDataIsInTheJson() {
		Sensor s = new Sensor().name( "nf-json" ).method( "x.Y.e" ).capture( "path", "#P0" ).capture( "size", "#P1" ).capture( "all", "{#P0, #P0}" );
		call( s, "/a\"b", 3 );
		java.io.StringWriter out = new java.io.StringWriter();
		new JsonSink( out, 0 ).accept( seen().get( 0 ) );
		String json = out.toString();
		Assertions.assertTrue( json.contains( "\"data\":{\"path\":\"/a\\\"b\",\"size\":3,\"all\":[\"/a\\\"b\",\"/a\\\"b\"]}" ), json );
	}

	@Test
	void aRuleReportsTheFieldsWhenItBlocks() {
		Sensor s = new Sensor().name( "nf-rule" ).method( "x.Y.f" ).capture( "path", "#P0" ).capture( "size", "#P1" ).description( "no" ).blockWhen( "#P1 < 10" );
		Assertions.assertThrows( org.openolly.advice.SensorException.class, () -> call( s, "/a", 3 ) );
		Event e = seen().stream().filter( x -> x.getRule().equals( "nf-rule-blocked" ) ).findFirst().get();
		Assertions.assertEquals( 3, e.getData().get( "size" ) );
	}

	@Test
	void aFieldThatCantBeWorkedOutIsNullAndTheRestIsStillRecorded() {
		Sensor s = new Sensor().name( "nf-null" ).method( "x.Y.g" ).capture( "path", "#P0" ).capture( "exists", "#P0.exists()" );
		call( s, "/a" );
		List<Event> out = seen();
		Assertions.assertEquals( 1, out.size() );
		Assertions.assertEquals( "/a", out.get( 0 ).getData().get( "path" ) );
		Assertions.assertTrue( out.get( 0 ).getData().containsKey( "exists" ) );
		Assertions.assertNull( out.get( 0 ).getData().get( "exists" ) );
	}
}
