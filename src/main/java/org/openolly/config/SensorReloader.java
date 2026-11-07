package org.openolly.config;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.openolly.AppScope;
import org.openolly.Instrumenter;
import org.openolly.JotScope;
import org.openolly.MethodLocator;
import org.openolly.Sensor;
import org.openolly.log.FluentLogger;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * Adds and removes sensors while the application runs, so a change to the jots file or the .jot files it lists takes effect
 * without a restart. The agent reads those files, once a second. Nothing connects to it, like the control file.
 *
 * A change is acted on once the files have stayed the same for a second, so a file that is still being written isn't read
 * half done. Then every file is read and checked before anything is touched, and the sensors are compared by name with the ones
 * that are loaded. A name that is new is added, one that is gone is removed, and one whose definition differs is replaced.
 *
 * It fails safe, in the same way the control file does.
 *
 *   A file that can't be read, or is not valid YAML, or whose sensors are not a list, changes nothing at all, and what is
 *   running stays as it is. The same goes if a sensor can't be made.
 *   A sensor that is wrong, such as a typo in an edit, is left out and said so, and the version of it that is running stays on.
 *   A replacement goes on before the old one comes off, so a sensor that can't be put on leaves the old one running.
 *
 * The entry points of the application, app: entry: in the jots file, follow it too. A call already inside an entry point when
 * they change finishes as it began, and only the calls that begin after are held to the new list, so nothing is lost but what
 * the old list would have recorded for requests already running. An entry list that is wrong leaves the running one as it is.
 *
 * Only sensors that came from the files are managed. The packages and ignore settings of the jots file are read
 * once at startup. -Djot.reload=false turns this off.
 */
public final class SensorReloader {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();

	private static final long POLL_MILLIS = 1000;

	private final File jots;
	private String settled;      // what the files looked like when they were last acted on
	private String pending = null;     // what they looked like at the last look, if that was a change not yet acted on
	private String lastProblem = null;

	/** What a reload did. error is null if it went through. */
	public static final class Result {
		public final List<String> added = new ArrayList<String>();
		public final List<String> removed = new ArrayList<String>();
		public final List<String> changed = new ArrayList<String>();
		/** The entry points now, if the jots file changed them. */
		public List<String> entry = null;
		public String error = null;

		public boolean isChange() {
			return !added.isEmpty() || !removed.isEmpty() || !changed.isEmpty() || entry != null;
		}

		@Override
		public String toString() {
			return error != null ? "error " + error : "added " + added + " removed " + removed + " changed " + changed + ( entry == null ? "" : " entry " + entry );
		}
	}

	/** A sensor as the files define it. */
	private static final class Definition {
		final String name;
		final JsonNode node;
		final String fingerprint;
		Definition(String name, JsonNode node) {
			this.name = name;
			this.node = node;
			this.fingerprint = node.toString();
		}
	}

	public SensorReloader(File jots) {
		this.jots = jots;
		this.settled = signature();
	}

	/** True if the agent follows its files, which needs a jots file and no -Djot.reload=false. The startup report says so. */
	public static boolean enabled() {
		return !"false".equalsIgnoreCase( System.getProperty( "jot.reload" ) ) && ConfigReader.jotsFile() != null;
	}

	/** Starts following the jots file the agent started with, unless -Djot.reload=false. */
	public static void startFromSystemProperties() {
		if ( !enabled() ) return;
		File jots = ConfigReader.jotsFile();
		SensorReloader reloader = new SensorReloader( jots );
		Thread t = new Thread( reloader::run, "jot-reload" );
		t.setDaemon( true );
		t.start();
	}

	private void run() {
		JotScope.enterForThread();
		while ( true ) {
			try {
				Thread.sleep( POLL_MILLIS );
				poll();
			} catch ( InterruptedException e ) {
				return;
			} catch ( Throwable t ) {
				// reloading must never take the application down
				problem( "error " + t );
			}
		}
	}

	/** Looks at the files and reloads if they changed and have stopped changing. Returns true if sensors were added, removed or replaced. */
	public synchronized boolean poll() {
		String now = signature();
		if ( now.equals( settled ) ) {
			pending = null;
			return false;
		}
		if ( !now.equals( pending ) ) {
			pending = now;
			return false;
		}
		pending = null;
		settled = now;
		return reload().isChange();
	}

	/** Reads the files and makes what is running match them, now. */
	public synchronized Result reload() {
		Result result = new Result();
		try {
			apply( result );
		} catch ( Throwable t ) {
			result.error = t.toString();
		}
		if ( result.error != null ) {
			problem( "was not reloaded, what is running stays as it is, " + result.error );
		} else {
			lastProblem = null;
		}
		return result;
	}

	// ---- reading

	/** The files in the order they are loaded, which is the order that decides which definition of a name wins. */
	private List<File> files(JsonNode root) {
		List<File> files = new ArrayList<File>();
		files.add( jots );
		File base = jots.getAbsoluteFile().getParentFile();
		for ( String entry : ConfigReader.listedPaths( root, base ) ) {
			if ( entry.isBlank() ) continue;
			File path = new File( entry.trim() );
			if ( !path.exists() ) continue;
			files.addAll( ConfigReader.jotFiles( path ) );
		}
		return files;
	}

	private JsonNode readJots() {
		try {
			return new ObjectMapper( new YAMLFactory() ).readTree( jots );
		} catch ( IOException e ) {
			return null;
		}
	}

	/** Where each file is, how big and when it was changed, which says when anything the agent reads has changed. */
	private String signature() {
		StringBuilder sb = new StringBuilder();
		JsonNode root = readJots();
		for ( File f : files( root ) ) {
			sb.append( f.getPath() ).append( '|' ).append( f.lastModified() ).append( '|' ).append( f.length() ).append( '\n' );
		}
		return sb.toString();
	}

	private static final class Parsed {
		final Map<String, Definition> defined = new LinkedHashMap<String, Definition>();
		// names of sensors that were written but are wrong, so the running version of each is left alone
		final Set<String> broken = new LinkedHashSet<String>();
		// the entry points the jots file asks for, or null if it says nothing about them or what it says is wrong
		List<String> entry = null;
	}

	private Parsed parse() throws IOException {
		ObjectMapper mapper = new ObjectMapper( new YAMLFactory() );
		JsonNode root;
		try {
			root = mapper.readTree( jots );
		} catch ( IOException e ) {
			throw new IOException( jots + " can't be read as YAML, " + firstLine( e ) );
		}
		if ( root == null || !root.isObject() ) throw new IOException( jots + " must be a YAML mapping" );
		Parsed parsed = new Parsed();
		parsed.entry = entryPoints( root );
		boolean main = true;
		for ( File f : files( root ) ) {
			JsonNode top;
			if ( main ) {
				top = root;
			} else {
				try {
					top = mapper.readTree( f );
				} catch ( IOException e ) {
					throw new IOException( f + " can't be read as YAML, " + firstLine( e ) );
				}
			}
			main = false;
			if ( top == null || !top.isObject() ) throw new IOException( f + " must be a YAML mapping" );
			JsonNode sensors = top.get( "sensors" );
			if ( sensors == null || sensors.isNull() ) continue;       // a bare sensors: is a list with nothing in it
			if ( !sensors.isArray() ) throw new IOException( f + " sensors must be a list" );
			for ( JsonNode node : sensors ) {
				String name = node.path( "name" ).isTextual() ? node.path( "name" ).asText() : null;
				if ( "example".equals( name ) ) continue;
				List<String> bad = JotValidator.sensorProblems( node );
				if ( !bad.isEmpty() ) {
					if ( name != null ) parsed.broken.add( name );
					logger.atSevere().log( "[JOT] ERROR: %s in %s %s. It was not loaded.", name, f, String.join( ", ", bad ) );
					continue;
				}
				if ( parsed.defined.containsKey( name ) ) continue;       // the first definition of a name wins
				parsed.defined.put( name, new Definition( name, node ) );
			}
		}
		return parsed;
	}

	/** The entry points the jots file asks for, null if they should stay as they are because it is wrong. */
	private List<String> entryPoints(JsonNode root) {
		try {
			List<String> entries = ConfigReader.entryPoints( root );
			if ( entries == null ) entries = AppScope.DEFAULT_ENTRY;
			for ( String entry : entries ) new MethodLocator( entry );    // one that can't be made is as wrong as one that is badly written
			return entries;
		} catch ( RuntimeException e ) {
			logger.atSevere().log( "[JOT] ERROR: %s in %s. The entry points that are running stay.", e.getMessage(), jots );
			return null;
		}
	}

	private static String firstLine(Exception e) {
		return e.getMessage() == null ? "" : e.getMessage().split( "\n" )[0];
	}

	// ---- applying

	private void apply(Result result) throws IOException {
		Parsed parsed = parse();
		applyEntry( parsed, result );

		Map<String, Sensor> live = new LinkedHashMap<String, Sensor>();
		for ( Sensor s : Sensor.getSensors() ) {
			// a sensor that didn't come from a file is not ours to manage
			if ( s.getName() != null && s.getFingerprint() != null && !s.isRetired() ) live.put( s.getName(), s );
		}

		List<Sensor> goneNow = new ArrayList<Sensor>();
		Map<String, Sensor> replaced = new LinkedHashMap<String, Sensor>();    // name to the one that is running now
		List<Definition> toMake = new ArrayList<Definition>();
		for ( Map.Entry<String, Sensor> e : live.entrySet() ) {
			Definition d = parsed.defined.get( e.getKey() );
			if ( d == null ) {
				if ( !parsed.broken.contains( e.getKey() ) ) goneNow.add( e.getValue() );
			} else if ( !d.fingerprint.equals( e.getValue().getFingerprint() ) ) {
				replaced.put( e.getKey(), e.getValue() );
				toMake.add( d );
			}
		}
		for ( Definition d : parsed.defined.values() ) {
			if ( !live.containsKey( d.name ) && !Sensor.exists( d.name ) ) toMake.add( d );
		}
		if ( goneNow.isEmpty() && toMake.isEmpty() ) return;

		// make everything before putting anything on, so one that can't be made changes nothing
		List<Sensor> made = new ArrayList<Sensor>();
		try {
			for ( Definition d : toMake ) made.add( ConfigReader.create( d.node ) );
		} catch ( Throwable t ) {
			for ( Sensor s : made ) s.retire();
			throw new IOException( "a sensor could not be made, " + t );
		}

		// new sensors start with what the control file says, before they can stop anything
		ControlFile.reapplyCurrent();

		// new ones on first, so a replacement that can't go on leaves the old one running
		Instrumenter.apply( List.of(), made );
		List<Sensor> off = new ArrayList<Sensor>( goneNow );
		for ( Sensor s : made ) {
			boolean on = Instrumenter.isInstalled( s );
			Sensor old = replaced.get( s.getName() );
			if ( !on ) {
				s.retire();
				if ( old != null ) logger.atWarning().log( "[JOT] " + s.getName() + " could not be put on, the earlier version stays on" );
				else logger.atWarning().log( "[JOT] " + s.getName() + " could not be put on" );
				continue;
			}
			if ( old != null ) {
				off.add( old );
				result.changed.add( s.getName() );
			} else {
				result.added.add( s.getName() );
			}
		}
		Instrumenter.apply( off, List.of() );
		for ( Sensor s : goneNow ) result.removed.add( s.getName() );
		report( result );
	}

	private void applyEntry(Parsed parsed, Result result) {
		if ( parsed.entry == null || parsed.entry.equals( AppScope.signatures() ) ) return;
		if ( Instrumenter.changeEntries( parsed.entry ) ) {
			result.entry = parsed.entry;
			say( "entry=changed", "entry=" + String.join( ",", parsed.entry ) );
		} else {
			logger.atWarning().log( "[JOT] the entry points in " + jots + " could not be put on, the earlier ones stay on" );
		}
	}

	private void report(Result result) {
		for ( String name : result.added ) say( name + "=added", "loaded=" + name );
		for ( String name : result.changed ) say( name + "=replaced", "loaded=" + name );
		for ( String name : result.removed ) say( name + "=removed", "unloaded=" + name );
	}

	private void say(String control, String config) {
		EventBus.publish( new Event( ControlFile.SENSOR, control, null, Event.Action.OBSERVED, "reload of " + jots ) );
		EventBus.publish( new Event( StartupReport.SENSOR, config, null, Event.Action.OBSERVED, "reload" ) );
	}

	private void problem(String text) {
		String message = "[JOT] sensors in " + jots + " " + text;
		if ( !message.equals( lastProblem ) ) {
			lastProblem = message;
			logger.atWarning().log( message );
			EventBus.publish( new Event( ControlFile.SENSOR, "warning", null, Event.Action.OBSERVED, message ) );
		}
	}
}
