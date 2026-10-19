package org.openolly;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openolly.advice.SensorException;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

class AppScopeTest {

	@AfterEach
	void noApplicationScopeLeftBehind() {
		AppScope.configure( List.of() );
		while ( AppScope.active() ) AppScope.leave();
	}

	private static class Recorder implements EventSink {
		final List<Event> events = new ArrayList<Event>();
		public void accept(Event e) { events.add( e ); }
	}

	private List<Object> fire(Sensor s) {
		return s.execute( "test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo", new Exception().getStackTrace() );
	}

	private Recorder run(Runnable call) {
		Recorder r = new Recorder();
		EventBus.configure( List.of( r ), 10 );
		try { call.run(); } finally { EventBus.shutdown(); }
		return r;
	}

	@Test
	void aJotWithNoScopesOnlyAppliesWhileTheApplicationIsRunning() {
		AppScope.configure( List.of( "a.b.Entry.handle" ) );
		Sensor s = new Sensor().name( "as-default" ).method( "a.b.Class.method" ).capture( "#P0" );
		Recorder r = run( () -> {
			Assertions.assertEquals( 0, fire( s ).size(), "outside an entry point" );
			AppScope.enter();
			Assertions.assertEquals( 1, fire( s ).size(), "inside one" );
			AppScope.enter();                            // an entry point that calls another
			AppScope.leave();
			Assertions.assertEquals( 1, fire( s ).size(), "still inside the outer one" );
			AppScope.leave();
			Assertions.assertEquals( 0, fire( s ).size(), "outside again" );
		} );
		Assertions.assertEquals( 2, r.events.size() );
	}

	@Test
	void aRuleWithNoScopesIsAppScopedToo() {
		AppScope.configure( List.of( "a.b.Entry.handle" ) );
		Sensor.protectAll( true );
		Sensor rule = new Sensor().name( "as-rule" ).description( "Seen" ).method( "a.b.Class.method" ).capture( "#P0" ).blockWhen( "true" );
		Recorder r = run( () -> {
			Assertions.assertDoesNotThrow( () -> fire( rule ), "a call in a startup thread isn't blocked" );
			AppScope.enter();
			Assertions.assertThrows( SensorException.class, () -> fire( rule ), "a call while the application runs is" );
			AppScope.leave();
		} );
		Assertions.assertEquals( List.of( "as-rule-blocked" ), r.events.stream().map( Event::getRule ).toList() );
	}

	@Test
	void aJotWithItsOwnScopesUsesThemAndAnEmptyListMeansAnywhere() {
		AppScope.configure( List.of( "a.b.Entry.handle" ) );
		Sensor own = new Sensor().name( "as-own" ).method( "a.b.Class.method" ).capture( "#P0" ).scope( "a.b.Class.outer" );
		Sensor anywhere = new Sensor().name( "as-anywhere" ).method( "a.b.Class.method" ).capture( "#P0" ).scopes( List.of() );
		run( () -> {
			AppScope.enter();
			Assertions.assertEquals( 0, fire( own ).size(), "the application running doesn't make its own scope active" );
			AppScope.leave();
			Assertions.assertEquals( 1, fire( anywhere ).size(), "scopes: [] applies outside the application too" );
			own.enterScopeScope( 0 );
			Assertions.assertEquals( 1, fire( own ).size(), "inside its own scope it applies, with no application running" );
			own.leaveScopeScope( 0 );
		} );
	}

	@Test
	void aJotOnTheEntryPointItselfAppliesAsTheApplicationStarts() {
		// the route sensor watches Servlet.service, which is also where the application starts. Its advice runs as the call begins,
		// before the thread counts as inside, and it must not be held back for that
		AppScope.configure( List.of( "a.b.Entry.handle", "@a.b.Marker" ) );
		Sensor route = new Sensor().name( "as-route" ).method( "a.b.Entry.handle" ).capture( "#P0" );
		Sensor marked = new Sensor().name( "as-marked" ).method( "@a.b.Marker" ).capture( "#P0" );
		Sensor elsewhere = new Sensor().name( "as-elsewhere" ).method( "a.b.Class.method" ).capture( "#P0" );
		Recorder r = run( () -> {
			Assertions.assertEquals( 1, fire( route ).size(), "outside, but it is on the entry point" );
			Assertions.assertEquals( 1, fire( marked ).size(), "the same for an annotation entry point" );
			Assertions.assertEquals( 0, fire( elsewhere ).size(), "a JOT on some other method still waits for the application" );
		} );
		Assertions.assertEquals( List.of( "as-route", "as-marked" ), r.events.stream().map( Event::getRule ).toList() );
	}

	@Test
	void withNoEntryPointsThereIsNoApplicationScopeAndEverythingApplies() {
		Sensor s = new Sensor().name( "as-none" ).method( "a.b.Class.method" ).capture( "#P0" );
		run( () -> Assertions.assertEquals( 1, fire( s ).size(), "nothing configured" ) );
		AppScope.configure( List.of() );
		run( () -> Assertions.assertEquals( 1, fire( s ).size(), "entry: [] leaves no scope" ) );
		AppScope.configure( null );
		Assertions.assertEquals( AppScope.DEFAULT_ENTRY.size(), AppScope.entries().size(), "no list is the servlet entry points" );
	}

	@Test
	void theApplicationScopeSaysNothingAboutItself() {
		AppScope.configure( List.of( "a.b.Entry.handle" ) );
		Sensor s = new Sensor().name( "as-quiet" ).method( "a.b.Class.method" ).capture( "#P0" );
		Recorder r = run( () -> {
			AppScope.enter();
			fire( s );
			AppScope.leave();
		} );
		Assertions.assertEquals( List.of( "as-quiet" ), r.events.stream().map( Event::getRule ).toList(), "no -active event, a request happening isn't news" );
	}

	@Test
	void theJotsFileSetsTheEntryPointsIncludingAnnotationsAndABadOneKeepsTheDefault(@TempDir Path dir) throws Exception {
		Files.writeString( dir.resolve( "none.jot" ), "sensors: []\n" );
		Path jots = dir.resolve( "jots.yaml" );
		Files.writeString( jots, "jots:\n- none.jot\napp:\n  packages:\n  - com.acme\n  entry:\n  - jakarta.servlet.Servlet.service\n  - '@dev.langchain4j.agent.tool.Tool'\n" );
		ConfigReader.readJotsFile( jots.toFile() );
		Assertions.assertEquals( 2, AppScope.entries().size() );
		Assertions.assertTrue( AppScope.entries().get( 1 ).isAnnotation() );
		Assertions.assertEquals( "dev.langchain4j.agent.tool.Tool", AppScope.entries().get( 1 ).annotationName() );

		Files.writeString( jots, "jots:\n- none.jot\napp:\n  entry: []\n" );
		ConfigReader.readJotsFile( jots.toFile() );
		Assertions.assertFalse( AppScope.configured(), "an empty list is no application scope" );

		Files.writeString( jots, "jots:\n- none.jot\n" );
		ConfigReader.readJotsFile( jots.toFile() );
		Assertions.assertEquals( AppScope.DEFAULT_ENTRY.size(), AppScope.entries().size(), "nothing said is the default" );

		int before = ConfigReader.getProblems().size();
		for ( String bad : List.of( "app:\n- com.acme\n", "app:\n  entry: javax.servlet.Servlet.service\n", "app:\n  entry:\n  - service\n",
				"app:\n  entry:\n  - 5\n", "app:\n  packages: []\n  entrys: []\n" ) ) {
			Files.writeString( jots, "jots:\n- none.jot\n" + bad );
			ConfigReader.readJotsFile( jots.toFile() );
		}
		Assertions.assertEquals( 5, ConfigReader.getProblems().size() - before, "each of them is said out loud" );
		Assertions.assertEquals( AppScope.DEFAULT_ENTRY.size(), AppScope.entries().size(), "and the default is used" );
	}
}
