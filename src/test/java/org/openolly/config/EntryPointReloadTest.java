package org.openolly.config;

import static org.openolly.DynamicSensorsTest.ENTRY;
import static org.openolly.DynamicSensorsTest.SLOTS;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openolly.AppScope;
import org.openolly.DynamicSensorsTest;
import org.openolly.DynamicSensorsTest.Entry;
import org.openolly.DynamicSensorsTest.Fixture;
import org.openolly.Instrumenter;
import org.openolly.Sensor;
import org.openolly.advice.SensorException;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

/**
 * The entry points of the application change while it runs. Every slot has a rule that blocks, with no scopes of its own, so it
 * applies only inside an entry point. A call made through handle, through relay or straight to the fixture is stopped or not
 * depending on whether that way in is an entry point at the time, which is how the test sees what is running.
 */
class EntryPointReloadTest {

	static final String HANDLE = ENTRY + ".handle";
	static final String RELAY = ENTRY + ".relay";

	@TempDir
	Path dir;
	File jots;
	SensorReloader reloader;
	List<Event> events;

	@BeforeAll
	static void attach() throws Exception {
		DynamicSensorsTest.attach();
	}

	@BeforeEach
	void setUp() throws Exception {
		Sensor.clearSensors();
		Sensor.protectAll( true );
		Sensor.applyControl( true, Map.of() );
		events = Collections.synchronizedList( new ArrayList<Event>() );
		EventBus.configure( List.of( (EventSink) events::add ), 10000 );
		jots = dir.resolve( "jot.yaml" ).toFile();
	}

	@AfterEach
	void tearDown() {
		ControlFile.current = null;
		Instrumenter.removeAll();
		Sensor.clearSensors();
		AppScope.configure( List.of() );
		while ( AppScope.active() ) AppScope.leave();
		EventBus.shutdown();
	}

	// ---- the files

	String rules() {
		Map<String, Integer> all = new TreeMap<String, Integer>();
		for ( int i = 0; i < SLOTS; i++ ) all.put( "dyn-" + i, i );
		return SensorReloaderTest.yamlFile( all );
	}

	void write(String entries, String text) throws IOException {
		String app = entries == null ? "" : "app:\n  entry:" + entries + "\n";
		Files.write( jots.toPath(), ( app + text ).getBytes( StandardCharsets.UTF_8 ) );
	}

	static String list(String... entries) {
		if ( entries.length == 0 ) return " []";
		StringBuilder sb = new StringBuilder();
		for ( String e : entries ) sb.append( "\n  - \"" ).append( e ).append( '"' );
		return sb.toString();
	}

	void start(String entries) throws Exception {
		write( entries, rules() );
		Instrumenter.removeAll();
		Sensor.clearSensors();
		ConfigReader.init( jots.getPath() );
		Instrumenter.instrument( DynamicSensorsTest.inst, Sensor.getSensors() );
		reloader = new SensorReloader( jots );
	}

	// ---- seeing

	/** True if a call that comes in this way is stopped. */
	static boolean via(String how, int target) {
		try {
			switch ( how ) {
				case "handle": new Entry().handle( new Fixture(), target ); break;
				case "relay": new Entry().relay( new Fixture(), target ); break;
				default: new Fixture().call( target, "x" ); break;
			}
			return false;
		} catch ( SensorException e ) {
			return true;
		}
	}

	/** Which ways in are held to the rules, checked on every slot. */
	String seen() {
		StringBuilder sb = new StringBuilder();
		for ( String how : new String[] { "handle", "relay", "direct" } ) {
			int blocked = 0;
			for ( int i = 0; i < SLOTS; i++ ) if ( via( how, i ) ) blocked++;
			Assertions.assertTrue( blocked == 0 || blocked == SLOTS, how + " was held to " + blocked + " of the rules" );
			if ( blocked > 0 ) sb.append( how ).append( ' ' );
		}
		return sb.toString().trim();
	}

	// ---- scenarios

	@Test
	void anEntryPointCanBeAdded() throws Exception {
		start( list( HANDLE ) );
		Assertions.assertEquals( "handle", seen() );
		write( list( HANDLE, RELAY ), rules() );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNull( r.error );
		Assertions.assertEquals( List.of( HANDLE, RELAY ), r.entry );
		Assertions.assertEquals( "handle relay", seen() );
		Assertions.assertEquals( List.of( HANDLE, RELAY ), AppScope.signatures() );
	}

	@Test
	void anEntryPointCanBeRemoved() throws Exception {
		start( list( HANDLE, RELAY ) );
		Assertions.assertEquals( "handle relay", seen() );
		write( list( RELAY ), rules() );
		Assertions.assertNull( reloader.reload().error );
		Assertions.assertEquals( "relay", seen() );
		write( list( HANDLE ), rules() );
		reloader.reload();
		Assertions.assertEquals( "handle", seen() );
	}

	@Test
	void anEmptyListMeansNoApplicationScopeAndSensorsApplyEverywhere() throws Exception {
		start( list( HANDLE ) );
		write( list(), rules() );
		reloader.reload();
		Assertions.assertEquals( "handle relay direct", seen() );
		write( list( RELAY ), rules() );
		reloader.reload();
		Assertions.assertEquals( "relay", seen() );
	}

	@Test
	void takingAwayTheAppSectionGoesBackToTheDefaults() throws Exception {
		start( list( HANDLE ) );
		write( null, rules() );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertEquals( AppScope.DEFAULT_ENTRY, r.entry );
		Assertions.assertEquals( "", seen(), "the servlet entry points are not what these calls come through" );
		write( list( RELAY ), rules() );
		reloader.reload();
		Assertions.assertEquals( "relay", seen() );
	}

	@Test
	void nothingHappensWhenTheEntryPointsAreTheSame() throws Exception {
		start( list( HANDLE, RELAY ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertFalse( r.isChange() );
		Assertions.assertNull( r.entry );
		Assertions.assertEquals( "handle relay", seen() );
	}

	@Test
	void anEntryListThatIsWrongLeavesTheRunningOnesAndStillAppliesTheSensors() throws Exception {
		start( list( HANDLE ) );
		for ( String bad : new String[] { " nonsense", " [nodots]", " [\"\"]", " [1, 2]", " {a: b}" } ) {
			write( bad, rules() + SensorReloaderTest.yamlRule( "extra", 3 ) );
			SensorReloader.Result r = reloader.reload();
			Assertions.assertNull( r.error, bad );
			Assertions.assertNull( r.entry, bad );
			Assertions.assertEquals( List.of( HANDLE ), AppScope.signatures(), bad );
			Assertions.assertEquals( "handle", seen(), bad );
			Assertions.assertEquals( List.of( "extra" ), r.added, bad + ", the sensors in the same edit still apply" );
			write( list( HANDLE ), rules() );
			reloader.reload();
		}
		write( null, "app: 5\n" + rules() );
		reloader.reload();
		Assertions.assertEquals( List.of( HANDLE ), AppScope.signatures(), "app that is not a mapping" );
		Assertions.assertEquals( "handle", seen() );
	}

	@Test
	void aSensorAddedInTheSameEditAsTheEntryPointsGoesOnUnderTheNewOnes() throws Exception {
		start( list( HANDLE ) );
		write( list( RELAY ), rules() + SensorReloaderTest.yamlRule( "late", 4 ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNull( r.error );
		Assertions.assertEquals( List.of( "late" ), r.added );
		Assertions.assertEquals( "relay", seen() );
	}

	@Test
	void garbageInTheJotsFileChangesNothing() throws Exception {
		start( list( HANDLE ) );
		Files.write( jots.toPath(), "app:\n  entry: [oops\n".getBytes( StandardCharsets.UTF_8 ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNotNull( r.error );
		Assertions.assertEquals( List.of( HANDLE ), AppScope.signatures() );
		Assertions.assertEquals( "handle", seen() );
	}

	@Test
	void theChangeIsSaid() throws Exception {
		start( list( HANDLE ) );
		write( list( RELAY ), rules() );
		reloader.reload();
		EventBus.shutdown();
		List<String> said = new ArrayList<String>();
		for ( Event e : new ArrayList<Event>( events ) ) said.add( e.getRule() + " " + e.getCapture() );
		Assertions.assertTrue( said.contains( "jot-control entry=changed" ), said.toString() );
		Assertions.assertTrue( said.stream().anyMatch( s -> s.startsWith( "jot-config entry=" ) ), said.toString() );
	}

	@Test
	void takingEverythingOffRestoresTheEntryPointClassExactly() throws Exception {
		byte[] before = DynamicSensorsTest.bytesOf( Entry.class );
		start( list( HANDLE ) );
		Assertions.assertFalse( java.util.Arrays.equals( before, DynamicSensorsTest.bytesOf( Entry.class ) ), "the entry point has advice" );
		write( list( HANDLE, RELAY ), rules() );
		reloader.reload();
		write( list( RELAY ), rules() );
		reloader.reload();
		write( list(), rules() );
		reloader.reload();
		Assertions.assertTrue( java.util.Arrays.equals( before, DynamicSensorsTest.bytesOf( Entry.class ) ),
			"with no entry points the class is as the application wrote it" );
		write( list( HANDLE ), rules() );
		reloader.reload();
		Instrumenter.removeAll();
		Assertions.assertTrue( java.util.Arrays.equals( before, DynamicSensorsTest.bytesOf( Entry.class ) ) );
	}

	// ---- calls that are running when the entry points change

	/** A fixture whose call waits, so a thread can be inside an entry point while the files change. */
	static class Parked extends Fixture {
		final CountDownLatch inside = new CountDownLatch( 1 );
		final CountDownLatch release = new CountDownLatch( 1 );
		@Override
		public void call(int i, String s) {
			inside.countDown();
			try {
				Assertions.assertTrue( release.await( 20, TimeUnit.SECONDS ) );
			} catch ( InterruptedException e ) {
				throw new RuntimeException( e );
			}
			super.call( i, s );
		}
	}

	/** Runs a call on its own thread, which stops inside it until release. Gives what the thread saw when it was done. */
	static final class Caller {
		final Parked parked = new Parked();
		volatile Throwable thrown;
		volatile boolean activeAfter = true;
		final Thread thread;

		Caller(boolean viaHandle, int target) {
			thread = new Thread( () -> {
				try {
					if ( viaHandle ) new Entry().handle( parked, target ); else new Entry().relay( parked, target );
				} catch ( Throwable t ) {
					thrown = t;
				}
				activeAfter = AppScope.active();
			} );
			thread.setDaemon( true );
		}

		void startAndWaitUntilInside() throws Exception {
			thread.start();
			Assertions.assertTrue( parked.inside.await( 20, TimeUnit.SECONDS ) );
		}

		void finish() throws Exception {
			parked.release.countDown();
			thread.join( 20000 );
			Assertions.assertFalse( thread.isAlive() );
		}
	}

	@Test
	void aCallInsideAnEntryPointThatIsRemovedFinishesAsItBegan() throws Exception {
		start( list( HANDLE ) );
		Caller c = new Caller( true, 2 );
		c.startAndWaitUntilInside();
		write( list( RELAY ), rules() );
		Assertions.assertNull( reloader.reload().error );
		Assertions.assertEquals( "relay", seen() );
		c.finish();
		Assertions.assertTrue( c.thrown instanceof SensorException, "it was in the application when it began, and is held to the rules until it ends, " + c.thrown );
		Assertions.assertFalse( c.activeAfter, "and the thread is not left inside the application" );
		Assertions.assertEquals( "relay", seen() );
	}

	@Test
	void aCallThatBeganOutsideAnEntryPointIsNotHeldWhenItBecomesOne() throws Exception {
		start( list( HANDLE ) );
		Caller c = new Caller( false, 2 );
		c.startAndWaitUntilInside();
		write( list( HANDLE, RELAY ), rules() );
		Assertions.assertNull( reloader.reload().error );
		c.finish();
		Assertions.assertNull( c.thrown, "it began before relay was an entry point" );
		Assertions.assertFalse( c.activeAfter );
		Assertions.assertEquals( "handle relay", seen() );
	}

	@Test
	void theDepthComesBackToZeroWhateverTheOrder() throws Exception {
		start( list( HANDLE, RELAY ) );
		List<Caller> callers = new ArrayList<Caller>();
		Random random = new Random( 5 );
		for ( int round = 0; round < 6; round++ ) {
			Caller c = new Caller( random.nextBoolean(), random.nextInt( SLOTS ) );
			c.startAndWaitUntilInside();
			callers.add( c );
			String[] now = switch ( random.nextInt( 4 ) ) {
				case 0 -> new String[] { HANDLE };
				case 1 -> new String[] { RELAY };
				case 2 -> new String[] {};
				default -> new String[] { HANDLE, RELAY };
			};
			write( list( now ), rules() );
			Assertions.assertNull( reloader.reload().error );
		}
		for ( Caller c : callers ) {
			c.finish();
			Assertions.assertFalse( c.activeAfter, "a thread was left inside the application" );
			Assertions.assertTrue( c.thrown == null || c.thrown instanceof SensorException, String.valueOf( c.thrown ) );
		}
		Assertions.assertFalse( AppScope.active() );
	}

	// ---- many changes

	@Test
	void randomChangesAlwaysMatchTheModel() throws Exception {
		for ( long seed = 1; seed <= 8; seed++ ) {
			start( list( HANDLE ) );
			Random random = new Random( seed );
			List<String> expected = List.of( HANDLE );
			for ( int step = 0; step < 40; step++ ) {
				int pick = random.nextInt( 7 );
				String entries;
				switch ( pick ) {
					case 0: entries = list( HANDLE ); expected = List.of( HANDLE ); break;
					case 1: entries = list( RELAY ); expected = List.of( RELAY ); break;
					case 2: entries = list( HANDLE, RELAY ); expected = List.of( HANDLE, RELAY ); break;
					case 3: entries = list(); expected = List.of(); break;
					case 4: entries = " [nodots]"; break;                  // wrong, so what is running stays
					case 5: entries = list( RELAY, HANDLE ); expected = List.of( RELAY, HANDLE ); break;
					default: entries = null; expected = AppScope.DEFAULT_ENTRY; break;
				}
				write( entries, rules() );
				Assertions.assertNull( reloader.reload().error, "seed " + seed + " step " + step );
				Assertions.assertEquals( expected, AppScope.signatures(), "seed " + seed + " step " + step );
				String want = expected.isEmpty() ? "handle relay direct"
					: ( expected.contains( HANDLE ) ? "handle " : "" ) + ( expected.contains( RELAY ) ? "relay" : "" );
				Assertions.assertEquals( want.trim(), seen(), "seed " + seed + " step " + step );
				Assertions.assertFalse( AppScope.active(), "seed " + seed + " step " + step );
			}
		}
	}

	@Test
	void callsKeepFlowingFromManyThreadsWhileTheEntryPointsChange() throws Exception {
		start( list( HANDLE ) );
		AtomicBoolean stop = new AtomicBoolean( false );
		List<Throwable> unexpected = Collections.synchronizedList( new ArrayList<Throwable>() );
		List<Thread> threads = new ArrayList<Thread>();
		for ( int t = 0; t < 4; t++ ) {
			Thread thread = new Thread( () -> {
				Random random = new Random();
				while ( !stop.get() ) {
					try {
						if ( random.nextBoolean() ) new Entry().handle( new Fixture(), random.nextInt( SLOTS ) );
						else new Entry().relay( new Fixture(), random.nextInt( SLOTS ) );
					} catch ( SensorException e ) {
						// stopped, which is what the rules are for
					} catch ( Throwable e ) {
						unexpected.add( e );
					}
					if ( AppScope.active() ) unexpected.add( new IllegalStateException( "still in the application scope" ) );
				}
			} );
			thread.setDaemon( true );
			threads.add( thread );
			thread.start();
		}
		Random random = new Random( 33 );
		String[][] choices = { { HANDLE }, { RELAY }, { HANDLE, RELAY }, {} };
		for ( int step = 0; step < 60; step++ ) {
			write( list( choices[random.nextInt( choices.length )] ), rules() );
			Assertions.assertNull( reloader.reload().error );
		}
		write( list( HANDLE ), rules() );
		reloader.reload();
		stop.set( true );
		for ( Thread thread : threads ) thread.join( 10000 );
		for ( Thread thread : threads ) Assertions.assertFalse( thread.isAlive() );
		Assertions.assertEquals( List.of(), unexpected.stream().map( Throwable::toString ).toList() );
		Assertions.assertEquals( "handle", seen() );
	}
}
