package org.openolly;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openolly.advice.SensorException;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

import net.bytebuddy.agent.ByteBuddyAgent;

/**
 * Sensors added and removed while the program runs, on real classes with the real instrumentation. Every rule here blocks, so
 * whether its advice is in a class is seen by whether a call throws. A model of which sensors should be on is compared with
 * what the classes do after every single step.
 */
public class DynamicSensorsTest {

	public static final int SLOTS = 10;
	public static final String FIXTURE = "org.openolly.DynamicSensorsTest$Fixture";
	public static final String ENTRY = "org.openolly.DynamicSensorsTest$Entry";

	/** The class the sensors watch, with one method for each slot. */
	public static class Fixture {
		public void m0(String s) {}
		public void m1(String s) {}
		public void m2(String s) {}
		public void m3(String s) {}
		public void m4(String s) {}
		public void m5(String s) {}
		public void m6(String s) {}
		public void m7(String s) {}
		public void m8(String s) {}
		public void m9(String s) {}

		public void call(int i, String s) {
			switch ( i ) {
				case 0: m0( s ); break;
				case 1: m1( s ); break;
				case 2: m2( s ); break;
				case 3: m3( s ); break;
				case 4: m4( s ); break;
				case 5: m5( s ); break;
				case 6: m6( s ); break;
				case 7: m7( s ); break;
				case 8: m8( s ); break;
				default: m9( s ); break;
			}
		}
	}

	/** The application's entry point. Sensors with no scopes of their own only apply while it runs. */
	public static class Entry {
		public void handle(Fixture f, int i) {
			f.call( i, "x" );
		}
		/** The same work as handle, by another way in, so a test can tell which of the two are entry points. */
		public void relay(Fixture f, int i) {
			f.call( i, "x" );
		}
		/** A second entry point, to be sensed itself. */
		public void other(String s) {}
	}

	public static Instrumentation inst;
	public static byte[] fixtureOriginal;

	@BeforeAll
	public static void attach() throws Exception {
		inst = ByteBuddyAgent.install();
		fixtureOriginal = bytesOf( Fixture.class );
	}

	@BeforeEach
	void setUp() {
		Sensor.clearSensors();    // other tests leave their sensors behind
		Sensor.protectAll( true );
		Sensor.applyControl( true, Map.of() );
		AppScope.configure( List.of( ENTRY + ".handle" ) );
		EventBus.configure( List.of( (EventSink) e -> {} ), 100 );
		Instrumenter.instrument( inst, List.of() );
	}

	@AfterEach
	void tearDown() {
		Instrumenter.removeAll();
		Sensor.clearSensors();
		AppScope.configure( List.of() );
		while ( AppScope.active() ) AppScope.leave();
		EventBus.shutdown();
	}

	// ---- helpers

	/** What the JVM would hand the last transformer to see for this class right now, which is what everything before it made of it. */
	public static byte[] bytesOf(Class<?> type) throws Exception {
		byte[][] seen = new byte[1][];
		String internal = type.getName().replace( '.', '/' );
		ClassFileTransformer probe = new ClassFileTransformer() {
			@Override
			public byte[] transform(ClassLoader loader, String name, Class<?> cls, java.security.ProtectionDomain pd, byte[] buffer) {
				if ( internal.equals( name ) ) seen[0] = buffer.clone();
				return null;
			}
		};
		inst.addTransformer( probe, true );
		try {
			inst.retransformClasses( type );
		} finally {
			inst.removeTransformer( probe );
		}
		return seen[0];
	}

	static Sensor rule(String name, String method) {
		return new Sensor().name( name ).description( "blocked " + name ).method( method ).capture( "#P0" ).blockWhen( "true" );
	}

	static String slotName(int slot) {
		return "dyn-" + slot;
	}

	public static String fixtureMethod(int target) {
		return FIXTURE + ".m" + target;
	}

	/** True if a call to this method of the fixture, made the way the application does, is stopped. */
	public static boolean blocked(int target) {
		try {
			new Entry().handle( new Fixture(), target );
			return false;
		} catch ( SensorException e ) {
			return true;
		}
	}

	public static Set<Integer> blockedNow() {
		Set<Integer> out = new TreeSet<Integer>();
		for ( int i = 0; i < SLOTS; i++ ) if ( blocked( i ) ) out.add( i );
		return out;
	}

	/** The test's own account of what should be on, one slot at a time. A slot is a sensor name and the method it watches. */
	class Model {
		final Sensor[] sensor = new Sensor[SLOTS];
		final int[] watches = new int[SLOTS];
		final int[] edits = new int[SLOTS];

		Set<Integer> expectedBlocked() {
			Set<Integer> out = new TreeSet<Integer>();
			for ( int s = 0; s < SLOTS; s++ ) if ( sensor[s] != null ) out.add( watches[s] );
			return out;
		}

		boolean on(int slot) {
			return sensor[slot] != null;
		}

		/** The next definition for this slot, a different method each edit. */
		Sensor next(int slot) {
			watches[slot] = ( slot + edits[slot]++ ) % SLOTS;
			return rule( slotName( slot ), fixtureMethod( watches[slot] ) );
		}

		void add(int slot) {
			if ( on( slot ) ) {
				Assertions.assertFalse( Instrumenter.add( sensor[slot] ), "adding a sensor that is on does nothing" );
				return;
			}
			Sensor made = next( slot );
			Assertions.assertTrue( Instrumenter.add( made ), "slot " + slot + " went on" );
			sensor[slot] = made;
		}

		void remove(int slot) {
			if ( !on( slot ) ) return;
			Assertions.assertTrue( Instrumenter.remove( sensor[slot] ), "slot " + slot + " came off" );
			Assertions.assertFalse( Instrumenter.remove( sensor[slot] ), "taking it off again does nothing" );
			Assertions.assertTrue( sensor[slot].isRetired() );
			sensor[slot] = null;
		}

		/** Off and on again under the same name, watching something else. */
		void edit(int slot) {
			if ( !on( slot ) ) return;
			Sensor old = sensor[slot];
			Sensor made = next( slot );
			Assertions.assertEquals( 1, Instrumenter.apply( List.of( old ), List.of( made ) ) );
			sensor[slot] = made;
		}

		void check(String step) {
			Assertions.assertEquals( expectedBlocked(), blockedNow(), step );
			int live = 0;
			for ( int s = 0; s < SLOTS; s++ ) if ( on( s ) ) live++;
			Assertions.assertEquals( live, Instrumenter.installedCount(), step + ", sensors installed" );
			Assertions.assertEquals( live, Sensor.getSensors().size(), step + ", sensors loaded" );
		}
	}

	// ---- scenarios

	@Test
	void aSensorAddedWhileRunningStartsWorkingAndOnceRemovedStops() {
		Assertions.assertEquals( Set.of(), blockedNow() );
		Sensor s = rule( "dyn-0", fixtureMethod( 3 ) );
		Assertions.assertTrue( Instrumenter.add( s ) );
		Assertions.assertEquals( Set.of( 3 ), blockedNow() );
		Assertions.assertTrue( Instrumenter.remove( s ) );
		Assertions.assertEquals( Set.of(), blockedNow() );
	}

	@Test
	void removingEverySensorPutsTheClassBackExactlyAsItWas() throws Exception {
		Model m = new Model();
		for ( int i = 0; i < SLOTS; i++ ) m.add( i );
		Assertions.assertFalse( Arrays.equals( fixtureOriginal, bytesOf( Fixture.class ) ), "it is instrumented" );
		for ( int i = 0; i < SLOTS; i++ ) m.remove( i );
		m.check( "all gone" );
		Assertions.assertArrayEquals( fixtureOriginal, bytesOf( Fixture.class ), "no advice is left behind" );
	}

	@Test
	void addAllRemoveAllManyTimesInEveryOrder() throws Exception {
		Model m = new Model();
		Random random = new Random( 7 );
		for ( int round = 0; round < 6; round++ ) {
			List<Integer> order = new ArrayList<Integer>();
			for ( int i = 0; i < SLOTS; i++ ) order.add( i );
			Collections.shuffle( order, random );
			for ( int slot : order ) {
				m.add( slot );
				m.check( "round " + round + " added " + slot );
			}
			Collections.shuffle( order, random );
			for ( int slot : order ) {
				m.remove( slot );
				m.check( "round " + round + " removed " + slot );
			}
			Assertions.assertArrayEquals( fixtureOriginal, bytesOf( Fixture.class ), "round " + round + " leaves nothing behind" );
		}
	}

	@Test
	void editingASensorChangesWhatItWatchesAndNothingElse() {
		Model m = new Model();
		for ( int i = 0; i < SLOTS; i++ ) m.add( i );
		for ( int round = 0; round < 3; round++ ) {
			for ( int i = 0; i < SLOTS; i++ ) {
				m.edit( i );
				m.check( "round " + round + " edited " + i );
			}
		}
	}

	@Test
	void addingTwiceAndRemovingTwiceChangeNothing() {
		Model m = new Model();
		m.add( 2 );
		m.add( 2 );
		m.check( "added twice" );
		m.remove( 2 );
		m.remove( 2 );
		m.check( "removed twice" );
	}

	@Test
	void aBatchOfChangesLandsTogether() {
		Model m = new Model();
		for ( int i = 0; i < SLOTS; i += 2 ) m.add( i );
		m.check( "evens" );
		List<Sensor> off = new ArrayList<Sensor>();
		List<Sensor> on = new ArrayList<Sensor>();
		for ( int i = 0; i < SLOTS; i++ ) {
			if ( m.on( i ) ) {
				off.add( m.sensor[i] );
				m.sensor[i] = null;
			} else {
				Sensor made = m.next( i );
				on.add( made );
				m.sensor[i] = made;
			}
		}
		Assertions.assertEquals( SLOTS / 2, Instrumenter.apply( off, on ) );
		m.check( "odds instead of evens" );
	}

	@Test
	void randomChurnWithManySeeds() throws Exception {
		for ( long seed = 1; seed <= 12; seed++ ) {
			Instrumenter.removeAll();
			Sensor.clearSensors();
			Instrumenter.instrument( inst, List.of() );
			Model m = new Model();
			Random random = new Random( seed );
			for ( int step = 0; step < 40; step++ ) {
				int slot = random.nextInt( SLOTS );
				String what;
				switch ( random.nextInt( 4 ) ) {
					case 0: what = "add"; m.add( slot ); break;
					case 1: what = "remove"; m.remove( slot ); break;
					case 2: what = "edit"; m.edit( slot ); break;
					default: what = "flip"; if ( m.on( slot ) ) m.remove( slot ); else m.add( slot ); break;
				}
				m.check( "seed " + seed + " step " + step + " " + what + " " + slot );
			}
			for ( int i = 0; i < SLOTS; i++ ) m.remove( i );
			m.check( "seed " + seed + " end" );
			Assertions.assertArrayEquals( fixtureOriginal, bytesOf( Fixture.class ), "seed " + seed + " leaves nothing behind" );
		}
	}

	@Test
	void theApplicationScopeSurvivesTheChurnAndStillWrapsTheSensors() {
		// a rule on the entry point itself only blocks if the application scope began before it looked
		Sensor onEntry = rule( "dyn-entry", ENTRY + ".handle" );
		Sensor outside = rule( "dyn-other", ENTRY + ".other" );
		Assertions.assertTrue( Instrumenter.add( onEntry ) );
		Assertions.assertThrows( SensorException.class, () -> new Entry().handle( new Fixture(), 0 ) );
		Assertions.assertFalse( AppScope.active(), "the scope was left again after the sensor stopped the call" );
		Assertions.assertTrue( Instrumenter.add( outside ) );
		Assertions.assertDoesNotThrow( () -> new Entry().other( "x" ), "other isn't an entry point, so a sensor on it waits for the application" );
		Model m = new Model();
		Random random = new Random( 3 );
		for ( int step = 0; step < 30; step++ ) {
			int slot = random.nextInt( SLOTS );
			if ( m.on( slot ) ) m.remove( slot ); else m.add( slot );
			Assertions.assertThrows( SensorException.class, () -> new Entry().handle( new Fixture(), 0 ), "step " + step + ", the entry point is still sensed in scope" );
			Assertions.assertFalse( AppScope.active(), "step " + step + ", the scope is left" );
		}
		Assertions.assertTrue( Instrumenter.remove( onEntry ) );
		Assertions.assertDoesNotThrow( () -> new Entry().handle( new Fixture(), 99 ), "with it removed the entry point works" );
		Assertions.assertTrue( Instrumenter.remove( outside ) );
	}

	@Test
	void aCallThatWasRunningWhenItsSensorWasRemovedFinishesCleanly() throws Exception {
		CountDownLatch inside = new CountDownLatch( 1 );
		CountDownLatch release = new CountDownLatch( 1 );
		String slowMethod = SlowEntry.class.getName() + ".handleSlow";
		Sensor slow = new Sensor().name( "dyn-slow" ).method( slowMethod ).capture( "#ARGS" );
		Assertions.assertTrue( Instrumenter.add( slow ) );
		AtomicInteger failures = new AtomicInteger();
		Thread t = new Thread( () -> {
			AppScope.enter();
			try {
				new SlowEntry( inside, release ).handleSlow();
			} catch ( Throwable e ) {
				failures.incrementAndGet();
			} finally {
				AppScope.leave();
			}
		} );
		t.start();
		Assertions.assertTrue( inside.await( 10, TimeUnit.SECONDS ) );
		Assertions.assertTrue( Instrumenter.remove( slow ), "removed while a call is inside" );
		release.countDown();
		t.join( 10000 );
		Assertions.assertFalse( t.isAlive() );
		Assertions.assertEquals( 0, failures.get(), "the call that was inside finished without trouble" );
		// and the same name can be used again, and works
		Sensor again = new Sensor().name( "dyn-slow" ).description( "slow" ).method( slowMethod ).capture( "#ARGS" ).blockWhen( "true" );
		Assertions.assertTrue( Instrumenter.add( again ) );
		AppScope.enter();
		try {
			Assertions.assertThrows( SensorException.class, () -> new SlowEntry( null, null ).handleSlow() );
		} finally {
			AppScope.leave();
		}
	}

	public static class SlowEntry {
		final CountDownLatch inside;
		final CountDownLatch release;
		public SlowEntry(CountDownLatch inside, CountDownLatch release) {
			this.inside = inside;
			this.release = release;
		}
		public void handleSlow() throws Exception {
			if ( inside == null ) return;
			inside.countDown();
			release.await( 10, TimeUnit.SECONDS );
		}
	}

	@Test
	void applicationThreadsKeepRunningWhileSensorsComeAndGo() throws Exception {
		AtomicBoolean stop = new AtomicBoolean( false );
		List<Throwable> unexpected = Collections.synchronizedList( new ArrayList<Throwable>() );
		AtomicInteger calls = new AtomicInteger();
		List<Thread> threads = new ArrayList<Thread>();
		for ( int t = 0; t < 4; t++ ) {
			Thread thread = new Thread( () -> {
				Random random = new Random();
				while ( !stop.get() ) {
					try {
						new Entry().handle( new Fixture(), random.nextInt( SLOTS ) );
					} catch ( SensorException e ) {
						// stopped, which is what the rules are for
					} catch ( Throwable e ) {
						unexpected.add( e );
					}
					calls.incrementAndGet();
					if ( AppScope.active() ) unexpected.add( new IllegalStateException( "left an entry point still in the application scope" ) );
				}
			} );
			thread.setDaemon( true );
			threads.add( thread );
			thread.start();
		}
		Model m = new Model();
		Random random = new Random( 11 );
		for ( int step = 0; step < 60; step++ ) {
			int slot = random.nextInt( SLOTS );
			if ( random.nextInt( 3 ) == 0 ) m.edit( slot );
			else if ( m.on( slot ) ) m.remove( slot ); else m.add( slot );
		}
		for ( int i = 0; i < SLOTS; i++ ) m.remove( i );
		stop.set( true );
		for ( Thread thread : threads ) thread.join( 10000 );
		for ( Thread thread : threads ) Assertions.assertFalse( thread.isAlive(), "no thread is stuck" );
		Assertions.assertEquals( List.of(), unexpected.stream().map( Throwable::toString ).toList() );
		Assertions.assertTrue( calls.get() > 0 );
		m.check( "after the threads stop" );
	}

	@Test
	void sensorIdsAreNeverReused() {
		Set<Integer> seen = new LinkedHashSet<Integer>();
		for ( int i = 0; i < 50; i++ ) {
			Sensor s = rule( "dyn-0", fixtureMethod( 1 ) );
			Assertions.assertTrue( seen.add( s.getIndex() ), "id " + s.getIndex() + " was used before" );
			Instrumenter.add( s );
			Instrumenter.remove( s );
			Assertions.assertSame( s, Sensor.getSensor( s.getIndex() ), "a removed sensor is still found by its id, so old advice never fails" );
		}
	}

	@Test
	void aRemovedSensorDoesNothingEvenIfItsAdviceIsStillThere() {
		Sensor s = rule( "dyn-0", fixtureMethod( 4 ) );
		Assertions.assertTrue( Instrumenter.add( s ) );
		Assertions.assertTrue( blocked( 4 ) );
		s.retire();
		Assertions.assertFalse( blocked( 4 ), "retired, though nothing took the advice out" );
		Assertions.assertFalse( s.isEnabled() );
		Assertions.assertFalse( s.isProtected() );
	}
}
