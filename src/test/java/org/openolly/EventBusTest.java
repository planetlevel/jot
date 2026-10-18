package org.openolly;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.advice.SensorException;
import org.openolly.reporting.ConsoleSink;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;
import org.openolly.reporting.ViolationsOnlySink;
import org.openolly.reporting.JsonSink;

class EventBusTest {

	static class Recorder implements EventSink {
		final List<Event> events = Collections.synchronizedList( new ArrayList<Event>() );
		boolean closed = false;
		public void accept(Event e) { events.add( e ); }
		public void close() { closed = true; }
	}

	private static Event event(String rule) {
		return new Event( rule, "value", Thread.currentThread().getStackTrace() );
	}

	@AfterEach
	void tearDown() {
		EventBus.shutdown();
	}

	@Test
	void testPublishWithNoSinksDoesNothing() {
		EventBus.configure( new ArrayList<EventSink>(), 10 );
		EventBus.publish( event( "a" ) );
		Assertions.assertEquals( 0, EventBus.getDropped() );
	}

	@Test
	void testEventsAreDeliveredInOrderAndSinksClosedOnShutdown() {
		Recorder r = new Recorder();
		EventBus.configure( List.of( r ), 100 );
		for ( int i = 0; i < 50; i++ ) EventBus.publish( event( "r" + i ) );
		EventBus.shutdown();
		Assertions.assertEquals( 50, r.events.size() );
		for ( int i = 0; i < 50; i++ ) Assertions.assertEquals( "r" + i, r.events.get( i ).getRule() );
		Assertions.assertTrue( r.closed );
	}

	@Test
	void testFullQueueDropsEventsInsteadOfBlocking() throws Exception {
		CountDownLatch release = new CountDownLatch( 1 );
		CountDownLatch started = new CountDownLatch( 1 );
		Recorder r = new Recorder() {
			public void accept(Event e) {
				started.countDown();
				try { release.await( 5, TimeUnit.SECONDS ); } catch ( InterruptedException ex ) { }
				super.accept( e );
			}
		};
		EventBus.configure( List.of( r ), 2 );
		EventBus.publish( event( "first" ) );
		Assertions.assertTrue( started.await( 5, TimeUnit.SECONDS ) );   // worker is now stuck in the sink
		for ( int i = 0; i < 10; i++ ) EventBus.publish( event( "x" ) );
		Assertions.assertEquals( 8, EventBus.getDropped() );             // 2 queued, 8 dropped
		release.countDown();
		EventBus.shutdown();
		Assertions.assertEquals( 3, r.events.size() );
	}

	@Test
	void testBrokenSinkDoesNotAffectOthers() {
		Recorder good = new Recorder();
		EventSink bad = e -> { throw new IllegalStateException( "boom" ); };
		PrintStream original = System.err;
		System.setErr( new PrintStream( new ByteArrayOutputStream() ) );
		try {
			EventBus.configure( List.of( bad, good ), 10 );
			EventBus.publish( event( "a" ) );
			EventBus.shutdown();
		} finally {
			System.setErr( original );
		}
		Assertions.assertEquals( 1, good.events.size() );
	}

	@Test
	void testViolationsOnlySkipsObservedEvents() {
		Recorder r = new Recorder();
		EventBus.configure( List.of( new ViolationsOnlySink( r ) ), 10 );
		EventBus.publish( event( "observed" ) );
		EventBus.publish( new Event( "blocked", "v", null, Event.Action.BLOCKED, "no" ) );
		EventBus.publish( new Event( "monitored", "v", null, Event.Action.MONITORED, "no" ) );
		EventBus.shutdown();
		Assertions.assertEquals( 2, r.events.size() );
		Assertions.assertEquals( "blocked", r.events.get( 0 ).getRule() );
	}

	@Test
	void testJsonSinkEscapesAndIncludesContextAndStack() {
		StringWriter out = new StringWriter();
		JsonSink sink = new JsonSink( out );
		StackTraceElement[] stack = { new StackTraceElement( "java.lang.Thread", "getStackTrace", "Thread.java", 1 ),
				new StackTraceElement( "com.acme.Foo", "bar", "Foo.java", 7 ) };
		sink.accept( new Event( "rule", "say \"hi\"\n\tback\\slash", stack ) );
		sink.accept( new Event( "rule", "x", stack, Event.Action.BLOCKED, "denied" ) );
		String[] lines = out.toString().split( "\n" );
		Assertions.assertEquals( 2, lines.length );
		Assertions.assertTrue( lines[0].contains( "\"capture\":\"say \\\"hi\\\"\\n\\tback\\\\slash\"" ), lines[0] );
		Assertions.assertTrue( lines[0].contains( "\"action\":\"observed\"" ) );
		Assertions.assertTrue( lines[0].contains( "\"method\":\"com.acme.Foo.bar(Foo.java:7)\"" ) );
		Assertions.assertTrue( lines[0].contains( "\"stack\":[\"com.acme.Foo.bar(Foo.java:7)\"]" ), lines[0] );
		for ( String field : List.of( "v", "time", "ts", "run", "host", "pid", "app", "id", "trace", "thread", "thread_id", "sensor" ) ) {
			Assertions.assertTrue( lines[0].contains( "\"" + field + "\":" ), field + " in " + lines[0] );
		}
		Assertions.assertTrue( lines[1].contains( "\"action\":\"blocked\"" ) );
		Assertions.assertTrue( lines[1].contains( "\"message\":\"denied\"" ) );
		Assertions.assertTrue( lines[1].contains( "\"stack\":[\"com.acme.Foo.bar(Foo.java:7)\"]" ), lines[1] );
	}

	@Test
	void testConsoleSinkShowsActionMessageAndCaller() {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		StackTraceElement[] stack = { new StackTraceElement( "java.lang.Thread", "getStackTrace", "Thread.java", 1 ),
				new StackTraceElement( "com.acme.Foo", "bar", "Foo.java", 7 ),
				new StackTraceElement( "com.acme.Main", "main", "Main.java", 3 ) };
		new ConsoleSink( new PrintStream( bytes ) ).accept( new Event( "block-it", "[ls]", stack, Event.Action.BLOCKED, "not allowed" ) );
		String text = bytes.toString();
		Assertions.assertTrue( text.contains( "BLOCKED block-it [ls]" ), text );
		Assertions.assertTrue( text.contains( "not allowed" ), text );
		Assertions.assertTrue( text.contains( "at com.acme.Foo.bar(Foo.java:7)" ), text );
		Assertions.assertTrue( text.contains( "from com.acme.Main.main(Main.java:3)" ), text );
	}

	@Test
	void testBlockingSensorPublishesOneBlockedEventWithItsMessage() {
		Recorder r = new Recorder();
		EventBus.configure( List.of( r ), 10 );
		Sensor s = new Sensor().method( "a.b.Class.method" ).capture( "#P0" ).exception( "Not allowed" );
		Assertions.assertThrows( SensorException.class,
				() -> s.execute( "test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo" ) );
		EventBus.shutdown();
		Assertions.assertEquals( 1, r.events.size() );
		Event e = r.events.get( 0 );
		Assertions.assertEquals( Event.Action.BLOCKED, e.getAction() );
		Assertions.assertEquals( "Not allowed", e.getMessage() );
		Assertions.assertEquals( "bar", e.getCapture() );
		Assertions.assertNotNull( e.getStack() );
	}

	@Test
	void testObservingSensorPublishesObservedEvent() {
		Recorder r = new Recorder();
		EventBus.configure( List.of( r ), 10 );
		Sensor s = new Sensor().method( "a.b.Class.method" ).capture( "#P0" );
		s.execute( "test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo" );
		EventBus.shutdown();
		Assertions.assertEquals( 1, r.events.size() );
		Assertions.assertEquals( Event.Action.OBSERVED, r.events.get( 0 ).getAction() );
	}

	@Test
	void testAddSinkStartsDeliveryWhenNothingIsConfigured() {
		EventBus.configure( new ArrayList<EventSink>(), 10 );
		Recorder r = new Recorder();
		EventBus.addSink( r );
		EventBus.publish( event( "late" ) );
		EventBus.shutdown();
		Assertions.assertEquals( 1, r.events.size() );
	}


	@Test
	void testJsonSinkCallSiteAndStackLimit() {
		StringWriter out = new StringWriter();
		StackTraceElement[] stack = { new StackTraceElement( "java.lang.Thread", "getStackTrace", "Thread.java", 1 ),
				new StackTraceElement( "com.acme.Foo", "bar", "Foo.java", 7 ),
				new StackTraceElement( "com.acme.Main", "main", "Main.java", 3 ),
				new StackTraceElement( "com.acme.Boot", "run", "Boot.java", 9 ) };
		new JsonSink( out, 2 ).accept( new Event( "rule", "x", stack ) );
		String line = out.toString();
		Assertions.assertTrue( line.contains( "\"call_site\":\"com.acme.Main.main(Main.java:3)\"" ), line );
		Assertions.assertTrue( line.contains( "\"stack\":[\"com.acme.Foo.bar(Foo.java:7)\",\"com.acme.Main.main(Main.java:3)\"]" ), line );

		StringWriter none = new StringWriter();
		new JsonSink( none, 0 ).accept( new Event( "rule", "x", stack ) );
		Assertions.assertFalse( none.toString().contains( "\"stack\"" ) );
	}


	// ---- observe, monitor and block

	@org.junit.jupiter.api.AfterEach
	void restoreProtection() {
		Sensor.protectAll( true );
	}

	private Recorder run(Runnable call) {
		Recorder r = new Recorder();
		EventBus.configure( List.of( r ), 10 );
		try {
			call.run();
		} finally {
			EventBus.shutdown();
		}
		return r;
	}

	private Sensor rule() {
		return new Sensor().method( "a.b.Class.method" ).capture( "#P0" ).exception( "Not allowed" );
	}

	private List<Object> fire(Sensor s) {
		return s.execute( "test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo" );
	}

	@Test
	void testRuleThatIsNotProtectingReportsAndLetsTheCallGoAhead() {
		Sensor s = rule().protect( false );
		java.util.concurrent.atomic.AtomicReference<List<Object>> out = new java.util.concurrent.atomic.AtomicReference<>();
		Recorder r = run( () -> out.set( fire( s ) ) );   // no exception escapes
		Assertions.assertEquals( "[bar]", SafeString.format( out.get(), false ) );
		Assertions.assertEquals( 1, r.events.size() );
		Event e = r.events.get( 0 );
		Assertions.assertEquals( Event.Action.MONITORED, e.getAction() );
		Assertions.assertEquals( s.getName() + "-monitored", e.getRule() );
		Assertions.assertEquals( "Not allowed", e.getMessage() );
		Assertions.assertEquals( "bar", e.getCapture() );
		Assertions.assertNotNull( e.getStack() );
	}

	@Test
	void testRuleProtectsByDefault() {
		Sensor s = rule();
		Assertions.assertTrue( s.isProtected() );
		Recorder r = run( () -> Assertions.assertThrows( SensorException.class, () -> fire( s ) ) );
		Assertions.assertEquals( Event.Action.BLOCKED, r.events.get( 0 ).getAction() );
		Assertions.assertEquals( s.getName() + "-blocked", r.events.get( 0 ).getRule() );
	}

	@Test
	void testTheGlobalSwitchMakesEveryRuleReportOnly() {
		Sensor.protectAll( false );
		Sensor s = rule();
		Assertions.assertFalse( s.isProtected() );
		Recorder r = run( () -> fire( s ) );
		Assertions.assertEquals( List.of( Event.Action.MONITORED ), r.events.stream().map( Event::getAction ).toList() );
	}

	@Test
	void testARuleCannotSwitchProtectionBackOnOverTheGlobalSwitch() {
		Sensor.protectAll( false );
		Sensor s = rule().protect( true );
		Assertions.assertFalse( s.isProtected() );
		Recorder r = run( () -> fire( s ) );
		Assertions.assertEquals( Event.Action.MONITORED, r.events.get( 0 ).getAction() );
	}

	@Test
	void testOneRuleCanBeStagedWhileOthersStillBlock() {
		Sensor staged = rule().protect( false );
		Sensor live = rule();
		Recorder r = run( () -> {
			fire( staged );
			Assertions.assertThrows( SensorException.class, () -> fire( live ) );
		} );
		Assertions.assertEquals( List.of( Event.Action.MONITORED, Event.Action.BLOCKED ),
				r.events.stream().map( Event::getAction ).toList() );
	}

	@Test
	void testSensorsWithoutAnExceptionObserveWhetherOrNotRulesProtect() {
		Sensor.protectAll( false );
		Sensor s = new Sensor().method( "a.b.Class.method" ).capture( "#P0" );
		Recorder r = run( () -> fire( s ) );
		Assertions.assertEquals( List.of( Event.Action.OBSERVED ), r.events.stream().map( Event::getAction ).toList() );
	}

	@Test
	void testAReportOnlyRuleWithNoCapturesStillReports() {
		Sensor s = new Sensor().method( "a.b.Class.method" ).exception( "No process creation" ).protect( false );
		Recorder r = run( () -> fire( s ) );
		Assertions.assertEquals( 1, r.events.size() );
		Assertions.assertEquals( Event.Action.MONITORED, r.events.get( 0 ).getAction() );
	}

	@Test
	void testASandboxReportsOnceWhenItsScopeIsEntered() {
		Sensor s = rule().scope( "a.b.Class.outer" ).scope( "a.b.Class.inner" );
		Recorder r = run( () -> {
			s.enterScopeScope( 0, new Object[] { "x" } );
			s.enterScopeScope( 1, new Object[] { "y" } );   // already inside, so not an entry
			s.leaveScopeScope( 1 );
			s.leaveScopeScope( 0 );
			s.enterScopeScope( 1, new Object[] { "z" } );   // a second entry
			s.leaveScopeScope( 1 );
		} );
		Assertions.assertEquals( 2, r.events.size() );
		Assertions.assertEquals( s.getName() + "-entered", r.events.get( 0 ).getRule() );
		Assertions.assertEquals( Event.Action.OBSERVED, r.events.get( 0 ).getAction() );
		Assertions.assertEquals( "[x]", r.events.get( 0 ).getCapture() );
	}

	@Test
	void testASensorWithNoExceptionDoesNotReportEnteringItsScope() {
		Sensor s = new Sensor().method( "a.b.Class.method" ).scope( "a.b.Class.outer" );
		Recorder r = run( () -> s.enterScopeScope( 0, null ) );
		Assertions.assertEquals( 0, r.events.size() );
	}

	@Test
	void testRuleThatDoesNotMatchReportsNothingInAnyMode() {
		Sensor s = new Sensor().method( "a.b.Class.method" ).capture( "#P0" ).matcher( "nomatch" ).exception( "x" ).protect( false );
		Recorder r = run( () -> fire( s ) );
		Assertions.assertTrue( r.events.isEmpty() );
	}

}
