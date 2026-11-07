package org.openolly.config;

import static org.openolly.DynamicSensorsTest.ENTRY;
import static org.openolly.DynamicSensorsTest.SLOTS;
import static org.openolly.DynamicSensorsTest.blockedNow;
import static org.openolly.DynamicSensorsTest.bytesOf;
import static org.openolly.DynamicSensorsTest.fixtureMethod;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openolly.AppScope;
import org.openolly.DynamicSensorsTest;
import org.openolly.Instrumenter;
import org.openolly.Sensor;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

/**
 * The files change while the program runs and the sensors follow, on real classes with the real instrumentation. Every rule
 * blocks, so what is running is seen by which calls throw. The test keeps its own account of what the files say, and after every
 * step compares what should be running with what is.
 */
class SensorReloaderTest {

	@TempDir
	Path dir;
	File jots;
	File rules;
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
		events = java.util.Collections.synchronizedList( new ArrayList<Event>() );
		EventBus.configure( List.of( (EventSink) events::add ), 10000 );
		rules = dir.resolve( "rules" ).toFile();
		Assertions.assertTrue( rules.mkdirs() );
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

	static String yamlRule(String name, int target) {
		return "- name: " + name + "\n"
			+ "  description: blocked " + name + "\n"
			+ "  methods:\n"
			+ "  - \"" + fixtureMethod( target ) + "\"\n"
			+ "  captures:\n"
			+ "    args: \"#P0\"\n"
			+ "  block-when: true\n";
	}

	static String yamlFile(Map<String, Integer> rulesInFile) {
		StringBuilder sb = new StringBuilder( "sensors:\n" );
		for ( Map.Entry<String, Integer> e : rulesInFile.entrySet() ) sb.append( yamlRule( e.getKey(), e.getValue() ) );
		return sb.toString();
	}

	void write(File f, String text) throws IOException {
		Files.write( f.toPath(), text.getBytes( StandardCharsets.UTF_8 ) );
	}

	void writeJots(String sensorsInJots) throws IOException {
		write( jots, "jots:\n- rules\napp:\n  entry:\n  - \"" + ENTRY + ".handle\"\n" + sensorsInJots );
	}

	File rulesFile(String name) {
		return new File( rules, name );
	}

	/** Starts the agent the way it starts, with whatever the files say now. */
	void start() throws Exception {
		Instrumenter.removeAll();
		Sensor.clearSensors();
		ConfigReader.init( jots.getPath() );
		Instrumenter.instrument( DynamicSensorsTest.inst, Sensor.getSensors() );
		reloader = new SensorReloader( jots );
	}

	Set<String> managedNames() {
		Set<String> names = new TreeSet<String>();
		for ( Sensor s : Sensor.getSensors() ) names.add( s.getName() );
		return names;
	}

	Set<Integer> targets(int... t) {
		Set<Integer> out = new TreeSet<Integer>();
		for ( int i : t ) out.add( i );
		return out;
	}

	// ---- scenarios

	@Test
	void nothingChangesWhenNothingChanged() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1, "dyn-2", 2 ) ) );
		writeJots( "" );
		start();
		Assertions.assertEquals( targets( 1, 2 ), blockedNow() );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNull( r.error );
		Assertions.assertFalse( r.isChange(), "what was loaded at startup matches the files, so nothing is replaced: " + r );
		Assertions.assertEquals( targets( 1, 2 ), blockedNow() );
		Assertions.assertEquals( 2, Instrumenter.installedCount() );
	}

	@Test
	void aSensorAddedToAFileStartsWorkingWithoutARestart() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		Assertions.assertEquals( targets( 1 ), blockedNow() );
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-5", 5 ) ) ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertEquals( List.of( "dyn-5" ), r.added );
		Assertions.assertEquals( targets( 1, 5 ), blockedNow() );
	}

	@Test
	void aSensorTakenOutOfAFileStopsWithoutARestart() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-2", 2 ) ) ) );
		writeJots( "" );
		start();
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-2", 2 ) ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertEquals( List.of( "dyn-1" ), r.removed );
		Assertions.assertEquals( targets( 2 ), blockedNow() );
	}

	@Test
	void aNewFileAndADeletedFile() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		write( rulesFile( "b.jot" ), yamlFile( Map.of( "dyn-2", 2 ) ) );
		reloader.reload();
		Assertions.assertEquals( targets( 1, 2 ), blockedNow() );
		Assertions.assertTrue( rulesFile( "a.jot" ).delete() );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertEquals( List.of( "dyn-1" ), r.removed );
		Assertions.assertEquals( targets( 2 ), blockedNow() );
	}

	@Test
	void sensorsInTheJotsFileItselfAreFollowedToo() throws Exception {
		writeJots( yamlFile( Map.of( "dyn-3", 3 ) ) );
		start();
		Assertions.assertEquals( targets( 3 ), blockedNow() );
		writeJots( yamlFile( Map.of( "dyn-4", 4 ) ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertEquals( List.of( "dyn-4" ), r.added );
		Assertions.assertEquals( List.of( "dyn-3" ), r.removed );
		Assertions.assertEquals( targets( 4 ), blockedNow() );
	}

	@Test
	void aSensorWhoseDefinitionChangedIsReplaced() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 6 ) ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertEquals( List.of( "dyn-1" ), r.changed );
		Assertions.assertEquals( targets( 6 ), blockedNow(), "it watches the new method and not the old" );
		Assertions.assertEquals( 1, Instrumenter.installedCount() );
		Assertions.assertEquals( Set.of( "dyn-1" ), managedNames(), "one sensor of that name, not two" );
	}

	@Test
	void everythingRemovedLeavesTheClassesExactlyAsTheyWere() throws Exception {
		Map<String, Integer> all = new LinkedHashMap<String, Integer>();
		for ( int i = 0; i < SLOTS; i++ ) all.put( "dyn-" + i, i );
		write( rulesFile( "a.jot" ), yamlFile( all ) );
		writeJots( "" );
		start();
		Assertions.assertEquals( SLOTS, blockedNow().size() );
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		reloader.reload();
		Assertions.assertEquals( Set.of(), blockedNow() );
		Assertions.assertEquals( 0, Instrumenter.installedCount() );
		Assertions.assertArrayEquals( DynamicSensorsTest.fixtureOriginal, bytesOf( DynamicSensorsTest.Fixture.class ) );
	}

	// ---- fails safe

	@Test
	void aFileThatIsNotValidYamlChangesNothingAtAll() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		write( rulesFile( "b.jot" ), yamlFile( Map.of( "dyn-2", 2 ) ) );
		writeJots( "" );
		start();
		// one file is broken while another has a good change in the same save, nothing at all is applied
		write( rulesFile( "a.jot" ), "sensors:\n- name: dyn-1\n  methods: [unclosed\n" );
		write( rulesFile( "b.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-2", 2, "dyn-7", 7 ) ) ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNotNull( r.error );
		Assertions.assertFalse( r.isChange() );
		Assertions.assertEquals( targets( 1, 2 ), blockedNow(), "what was running is still running" );
		// fixed, and everything lands
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		r = reloader.reload();
		Assertions.assertNull( r.error );
		Assertions.assertEquals( targets( 1, 2, 7 ), blockedNow() );
	}

	@Test
	void aJotsFileThatIsBrokenChangesNothing() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		write( jots, "jots: [oops\n" );
		Assertions.assertNotNull( reloader.reload().error );
		Assertions.assertEquals( targets( 1 ), blockedNow() );
		write( jots, "" );     // empty, which is no mapping
		Assertions.assertNotNull( reloader.reload().error );
		Assertions.assertEquals( targets( 1 ), blockedNow() );
	}

	@Test
	void sensorsThatAreNotAListChangeNothing() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		write( rulesFile( "a.jot" ), "sensors:\n  dyn-1: 1\n" );
		Assertions.assertNotNull( reloader.reload().error );
		Assertions.assertEquals( targets( 1 ), blockedNow() );
	}

	@Test
	void aSensorWithAMistakeKeepsItsRunningVersionAndTheRestOfTheFileStillApplies() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-2", 2 ) ) ) );
		writeJots( "" );
		start();
		// dyn-1 gets a typo in an edit that also moves it, dyn-2 is edited well, dyn-3 is new and well written
		write( rulesFile( "a.jot" ),
			"sensors:\n"
			+ "- name: dyn-1\n  description: blocked dyn-1\n  methods:\n  - \"" + fixtureMethod( 8 ) + "\"\n  captures:\n    args: \"#P0\"\n  block-when: true\n  bogus-setting: 1\n"
			+ yamlRule( "dyn-2", 9 ) + yamlRule( "dyn-3", 3 ) );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNull( r.error );
		Assertions.assertEquals( targets( 1, 9, 3 ), blockedNow(), "dyn-1 is still the old one on 1, dyn-2 moved to 9, dyn-3 is new" );
		// the mistake is mended
		write( rulesFile( "a.jot" ), yamlRule( "dyn-1", 8 ).replaceFirst( "^", "sensors:\n" ) + yamlRule( "dyn-2", 9 ) + yamlRule( "dyn-3", 3 ) );
		reloader.reload();
		Assertions.assertEquals( targets( 8, 9, 3 ), blockedNow() );
	}

	@Test
	void aSensorWithAMistakeThatWasNeverRunningIsLeftOut() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		write( rulesFile( "a.jot" ), yamlRule( "dyn-1", 1 ).replaceFirst( "^", "sensors:\n" ) + "- name: Not A Good Name\n  methods:\n  - \"" + fixtureMethod( 2 ) + "\"\n" );
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNull( r.error );
		Assertions.assertEquals( targets( 1 ), blockedNow() );
		Assertions.assertEquals( Set.of( "dyn-1" ), managedNames() );
	}

	@Test
	void theFirstDefinitionOfANameWinsAndTheNextTakesOverWhenItGoes() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		write( rulesFile( "b.jot" ), yamlFile( Map.of( "dyn-1", 2 ) ) );
		writeJots( "" );
		start();
		Assertions.assertEquals( targets( 1 ), blockedNow() );
		Assertions.assertTrue( rulesFile( "a.jot" ).delete() );
		reloader.reload();
		Assertions.assertEquals( targets( 2 ), blockedNow(), "the later definition is used now" );
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 4 ) ) );
		reloader.reload();
		Assertions.assertEquals( targets( 4 ), blockedNow(), "and the earlier one wins again when it comes back" );
		Assertions.assertEquals( 1, Instrumenter.installedCount() );
	}

	@Test
	void aSensorThatDidNotComeFromAFileIsNotTouched() throws Exception {
		writeJots( "" );
		start();
		Sensor mine = new Sensor().name( "dyn-mine" ).description( "mine" ).method( fixtureMethod( 5 ) ).capture( "#P0" ).blockWhen( "true" );
		Assertions.assertTrue( Instrumenter.add( mine ) );
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		reloader.reload();
		Assertions.assertEquals( targets( 1, 5 ), blockedNow() );
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		reloader.reload();
		Assertions.assertEquals( targets( 5 ), blockedNow(), "the one made in code is still on" );
	}

	@Test
	void aNewSensorStartsWithWhatTheControlFileSays() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		File control = dir.resolve( "control.yaml" ).toFile();
		write( control, "v: 1\nprotect: true\nsensors:\n  dyn-2:\n    protect: false\n  dyn-3:\n    enabled: false\n" );
		ControlFile c = new ControlFile( control.toPath() );
		Assertions.assertTrue( c.poll() );
		ControlFile.current = c;
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-2", 2, "dyn-3", 3, "dyn-4", 4 ) ) ) );
		reloader.reload();
		Assertions.assertEquals( targets( 1, 4 ), blockedNow(), "dyn-2 is set to monitor and dyn-3 is off, they were never able to stop a call" );
	}

	// ---- the polling

	@Test
	void aChangeIsActedOnOnlyOnceTheFilesHaveStoppedChanging() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		Assertions.assertFalse( reloader.poll(), "nothing changed" );
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-2", 2 ) ) ) );
		Assertions.assertFalse( reloader.poll(), "seen once, so it may still be being written" );
		Assertions.assertEquals( targets( 1 ), blockedNow() );
		// still changing, so still waiting
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-2", 2, "dyn-3", 3 ) ) ) );
		Assertions.assertFalse( reloader.poll() );
		Assertions.assertEquals( targets( 1 ), blockedNow() );
		Assertions.assertTrue( reloader.poll(), "the same twice in a row, so it is acted on" );
		Assertions.assertEquals( targets( 1, 2, 3 ), blockedNow() );
		Assertions.assertFalse( reloader.poll(), "and then it is quiet again" );
		Assertions.assertFalse( reloader.poll() );
	}

	@Test
	void aBrokenFileIsNotRetriedUntilItChangesAgain() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( Map.of( "dyn-1", 1 ) ) );
		writeJots( "" );
		start();
		write( rulesFile( "a.jot" ), "sensors: [oops\n" );
		reloader.poll();
		Assertions.assertFalse( reloader.poll() );
		for ( int i = 0; i < 5; i++ ) Assertions.assertFalse( reloader.poll() );
		Assertions.assertEquals( targets( 1 ), blockedNow() );
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-2", 2 ) ) ) );
		reloader.poll();
		Assertions.assertTrue( reloader.poll() );
		Assertions.assertEquals( targets( 1, 2 ), blockedNow() );
	}

	// ---- what it says

	@Test
	void everyChangeIsSaidInAnEvent() throws Exception {
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-1", 1, "dyn-2", 2 ) ) ) );
		writeJots( "" );
		start();
		write( rulesFile( "a.jot" ), yamlFile( new TreeMap<String, Integer>( Map.of( "dyn-2", 3, "dyn-3", 4 ) ) ) );
		reloader.reload();
		EventBus.shutdown();
		List<String> said = new ArrayList<String>();
		for ( Event e : new ArrayList<Event>( events ) ) said.add( e.getRule() + " " + e.getCapture() );
		Collections.sort( said );
		Assertions.assertTrue( said.contains( "jot-control dyn-3=added" ), said.toString() );
		Assertions.assertTrue( said.contains( "jot-control dyn-2=replaced" ), said.toString() );
		Assertions.assertTrue( said.contains( "jot-control dyn-1=removed" ), said.toString() );
		Assertions.assertTrue( said.contains( "jot-config loaded=dyn-3" ), said.toString() );
		Assertions.assertTrue( said.contains( "jot-config loaded=dyn-2" ), said.toString() );
		Assertions.assertTrue( said.contains( "jot-config unloaded=dyn-1" ), said.toString() );
	}

	// ---- many changes, in every order

	/** What the files say, as the test sees it. */
	class Config {
		final Map<String, Map<String, Integer>> byFile = new TreeMap<String, Map<String, Integer>>();
		final Set<String> garbled = new TreeSet<String>();
		final Set<String> mistaken = new TreeSet<String>();      // sensors written with a mistake, by file and name

		void write(String file) throws IOException {
			if ( !byFile.containsKey( file ) ) {
				Files.deleteIfExists( rulesFile( file ).toPath() );
				return;
			}
			if ( garbled.contains( file ) ) {
				SensorReloaderTest.this.write( rulesFile( file ), "sensors:\n- name: [broken\n  methods: {\n" );
				return;
			}
			StringBuilder sb = new StringBuilder( "sensors:\n" );
			for ( Map.Entry<String, Integer> e : byFile.get( file ).entrySet() ) {
				String rule = yamlRule( e.getKey(), e.getValue() );
				if ( mistaken.contains( file + "/" + e.getKey() ) ) rule += "  bogus-setting: 1\n";
				sb.append( rule );
			}
			SensorReloaderTest.this.write( rulesFile( file ), sb.toString() );
		}

		/** The sensors that should be running if the files are read, name to the method it watches. */
		Map<String, Integer> desired(Map<String, Integer> running) {
			Map<String, Integer> out = new TreeMap<String, Integer>();
			Set<String> broken = new TreeSet<String>();
			for ( Map.Entry<String, Map<String, Integer>> f : byFile.entrySet() ) {
				for ( Map.Entry<String, Integer> r : f.getValue().entrySet() ) {
					if ( mistaken.contains( f.getKey() + "/" + r.getKey() ) ) broken.add( r.getKey() );
					else out.putIfAbsent( r.getKey(), r.getValue() );
				}
			}
			for ( String name : broken ) {
				if ( !out.containsKey( name ) && running.containsKey( name ) ) out.put( name, running.get( name ) );
			}
			return out;
		}
	}

	static final String[] FILES = { "a.jot", "b.jot", "c.jot", "d.jot" };

	private void churn(long seed, int steps) throws Exception {
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		writeJots( "" );
		start();
		Config files = new Config();
		files.byFile.put( "a.jot", new TreeMap<String, Integer>() );
		Map<String, Integer> running = new TreeMap<String, Integer>();
		Random random = new Random( seed );
		for ( int step = 0; step < steps; step++ ) {
			String file = FILES[random.nextInt( FILES.length )];
			String name = "dyn-" + random.nextInt( SLOTS );
			String what;
			switch ( random.nextInt( 8 ) ) {
				case 0: case 1:
					what = "put " + name;
					files.byFile.computeIfAbsent( file, k -> new TreeMap<String, Integer>() ).put( name, random.nextInt( SLOTS ) );
					files.mistaken.remove( file + "/" + name );
					break;
				case 2:
					what = "drop " + name;
					if ( files.byFile.containsKey( file ) ) files.byFile.get( file ).remove( name );
					files.mistaken.remove( file + "/" + name );
					break;
				case 3:
					what = "delete file " + file;
					files.byFile.remove( file );
					files.garbled.remove( file );
					break;
				case 4:
					what = "garble file " + file;
					if ( files.byFile.containsKey( file ) ) files.garbled.add( file );
					break;
				case 5:
					what = "repair file " + file;
					files.garbled.remove( file );
					break;
				case 6:
					what = "mistake in " + name;
					if ( files.byFile.containsKey( file ) && files.byFile.get( file ).containsKey( name ) ) files.mistaken.add( file + "/" + name );
					break;
				default:
					what = "empty file " + file;
					if ( files.byFile.containsKey( file ) ) files.byFile.get( file ).clear();
					break;
			}
			for ( String f : FILES ) files.write( f );
			files.write( "a.jot" );
			SensorReloader.Result r = reloader.reload();
			if ( files.garbled.isEmpty() ) {
				Assertions.assertNull( r.error, "seed " + seed + " step " + step + " " + what );
				running = files.desired( running );
			} else {
				Assertions.assertNotNull( r.error, "seed " + seed + " step " + step + " " + what + ", a garbled file is not applied" );
			}
			String where = "seed " + seed + " step " + step + " " + what + ", running " + running;
			Set<Integer> expected = new TreeSet<Integer>( running.values() );
			Assertions.assertEquals( expected, blockedNow(), where );
			Assertions.assertEquals( running.keySet(), managedNames(), where + ", sensors loaded" );
			Assertions.assertEquals( running.size(), Instrumenter.installedCount(), where + ", sensors installed" );
		}
		// everything out, and nothing is left behind
		for ( String f : FILES ) {
			files.byFile.remove( f );
			files.garbled.remove( f );
			Files.deleteIfExists( rulesFile( f ).toPath() );
		}
		SensorReloader.Result r = reloader.reload();
		Assertions.assertNull( r.error );
		Assertions.assertEquals( Set.of(), blockedNow(), "seed " + seed + " end" );
		Assertions.assertEquals( 0, Instrumenter.installedCount() );
		Assertions.assertArrayEquals( DynamicSensorsTest.fixtureOriginal, bytesOf( DynamicSensorsTest.Fixture.class ), "seed " + seed + " leaves nothing behind" );
	}

	@Test
	void randomChangesToTheFilesAcrossManySeeds() throws Exception {
		for ( long seed = 1; seed <= 8; seed++ ) {
			tearDown();
			setUpAgain();
			churn( seed, 40 );
		}
	}

	private void setUpAgain() throws Exception {
		Sensor.clearSensors();
		Sensor.protectAll( true );
		Sensor.applyControl( true, Map.of() );
		events.clear();
		EventBus.configure( List.of( (EventSink) events::add ), 10000 );
		File[] left = rules.listFiles();
		if ( left != null ) for ( File f : left ) Files.deleteIfExists( f.toPath() );
	}

	@Test
	void addEverySensorRemoveEverySensorInEveryOrder() throws Exception {
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		writeJots( "" );
		start();
		Random random = new Random( 5 );
		for ( int round = 0; round < 5; round++ ) {
			List<Integer> order = new ArrayList<Integer>();
			for ( int i = 0; i < SLOTS; i++ ) order.add( i );
			Collections.shuffle( order, random );
			Map<String, Integer> now = new TreeMap<String, Integer>();
			for ( int slot : order ) {
				now.put( "dyn-" + slot, ( slot + round ) % SLOTS );
				write( rulesFile( "a.jot" ), yamlFile( now ) );
				reloader.reload();
				Assertions.assertEquals( new TreeSet<Integer>( now.values() ), blockedNow(), "round " + round + " added " + slot );
			}
			Collections.shuffle( order, random );
			for ( int slot : order ) {
				now.remove( "dyn-" + slot );
				write( rulesFile( "a.jot" ), yamlFile( now ) );
				reloader.reload();
				Assertions.assertEquals( new TreeSet<Integer>( now.values() ), blockedNow(), "round " + round + " removed " + slot );
			}
			Assertions.assertEquals( 0, Instrumenter.installedCount() );
			Assertions.assertArrayEquals( DynamicSensorsTest.fixtureOriginal, bytesOf( DynamicSensorsTest.Fixture.class ), "round " + round );
		}
		// all at once, in both directions
		Map<String, Integer> all = new TreeMap<String, Integer>();
		for ( int i = 0; i < SLOTS; i++ ) all.put( "dyn-" + i, i );
		write( rulesFile( "a.jot" ), yamlFile( all ) );
		reloader.reload();
		Assertions.assertEquals( SLOTS, blockedNow().size() );
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		reloader.reload();
		Assertions.assertEquals( 0, blockedNow().size() );
	}

	@Test
	void theApplicationScopeStillWrapsTheSensorsAfterReloads() throws Exception {
		// a rule on the entry point itself blocks only if the application scope began before it looked
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		writeJots( "" );
		start();
		Random random = new Random( 9 );
		Map<String, Integer> now = new TreeMap<String, Integer>();
		for ( int step = 0; step < 20; step++ ) {
			String name = "dyn-" + random.nextInt( SLOTS );
			if ( now.containsKey( name ) ) now.remove( name ); else now.put( name, random.nextInt( SLOTS ) );
			StringBuilder text = new StringBuilder( yamlFile( now ) );
			text.append( "- name: dyn-entry\n  description: entry\n  methods:\n  - \"" + ENTRY + ".handle\"\n  captures:\n    args: \"#P0\"\n  block-when: true\n" );
			write( rulesFile( "a.jot" ), text.toString() );
			reloader.reload();
			Assertions.assertThrows( org.openolly.advice.SensorException.class, () -> new DynamicSensorsTest.Entry().handle( new DynamicSensorsTest.Fixture(), 99 ), "step " + step );
			Assertions.assertFalse( AppScope.active(), "step " + step + ", the scope was left" );
		}
	}

	@Test
	void callsKeepFlowingFromManyThreadsWhileTheFilesChange() throws Exception {
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		writeJots( "" );
		start();
		java.util.concurrent.atomic.AtomicBoolean stop = new java.util.concurrent.atomic.AtomicBoolean( false );
		List<Throwable> unexpected = Collections.synchronizedList( new ArrayList<Throwable>() );
		List<Thread> threads = new ArrayList<Thread>();
		for ( int t = 0; t < 4; t++ ) {
			Thread thread = new Thread( () -> {
				Random random = new Random();
				while ( !stop.get() ) {
					try {
						new DynamicSensorsTest.Entry().handle( new DynamicSensorsTest.Fixture(), random.nextInt( SLOTS ) );
					} catch ( org.openolly.advice.SensorException e ) {
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
		Random random = new Random( 21 );
		Map<String, Integer> now = new TreeMap<String, Integer>();
		for ( int step = 0; step < 40; step++ ) {
			String name = "dyn-" + random.nextInt( SLOTS );
			if ( now.containsKey( name ) && random.nextBoolean() ) now.remove( name ); else now.put( name, random.nextInt( SLOTS ) );
			write( rulesFile( "a.jot" ), yamlFile( now ) );
			Assertions.assertNull( reloader.reload().error );
		}
		write( rulesFile( "a.jot" ), "sensors: []\n" );
		reloader.reload();
		stop.set( true );
		for ( Thread thread : threads ) thread.join( 10000 );
		for ( Thread thread : threads ) Assertions.assertFalse( thread.isAlive() );
		Assertions.assertEquals( List.of(), unexpected.stream().map( Throwable::toString ).toList() );
		Assertions.assertEquals( Set.of(), blockedNow() );
		Assertions.assertEquals( 0, Instrumenter.installedCount() );
	}
}
