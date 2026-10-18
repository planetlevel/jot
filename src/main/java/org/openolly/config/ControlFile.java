package org.openolly.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.openolly.JotScope;
import org.openolly.Sensor;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * Lets an operator switch rules between monitor and block while the application runs, with no way in for
 * anything from outside. The agent reads a file, once a second. Nothing connects to the agent.
 *
 *   -Djot.control=/etc/jot/control.yaml
 *
 *   v: 1
 *   protect: true
 *   sensors:
 *     cve-log4shell-no-exec:
 *       protect: false
 *     get-ciphers:
 *       enabled: false
 *
 * protect is the master switch. When false, every rule only reports. Under sensors, each name has the settings
 * for that sensor or rule. protect is false to report only and true to block, for a rule, and it takes priority over
 * the rule's own protect in its .jot file. enabled is false to switch a sensor or rule off, so a sensor records
 * nothing and a rule neither blocks nor reports, and true to switch on one the .jot file wrote with enabled: false.
 * A setting that isn't listed goes back to its .jot file. The older rules map, a rule name and true or false for
 * protect, is still read. -Djot.protect=false can't be overridden from here.
 *
 * It fails safe. A file that is missing, unreadable, too large or invalid changes nothing, and the last good
 * settings stay in force. Each change is published as an event from the sensor "jot-control" so the log
 * shows when protection was lowered or restored.
 */
public final class ControlFile {

	static final String SENSOR = "jot-control";
	private static final int MAX_BYTES = 64 * 1024;
	private static final long POLL_MILLIS = 1000;

	private final Path path;
	private String lastText = null;
	private boolean master = true;
	private Map<String, Boolean> rules = new LinkedHashMap<String, Boolean>();
	private Map<String, Boolean> enabled = new LinkedHashMap<String, Boolean>();
	private boolean warnedPermissions = false;
	private String lastProblem = null;

	public ControlFile(Path path) {
		this.path = path;
	}

	/** Starts following the file named by -Djot.control, if there is one. */
	public static void startFromSystemProperties() {
		String name = System.getProperty( "jot.control" );
		if ( name == null || name.trim().isEmpty() ) return;
		ControlFile control = new ControlFile( Paths.get( name.trim() ) );
		control.poll();
		Thread t = new Thread( control::run, "jot-control" );
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
				// the control file must never take the application down
				problem( "error " + t );
			}
		}
	}

	/** Reads the file and applies it if it changed. Returns true if settings were applied. */
	public synchronized boolean poll() {
		String text;
		try {
			if ( !Files.isRegularFile( path ) ) return false;
			if ( Files.size( path ) > MAX_BYTES ) {
				problem( "is larger than " + MAX_BYTES + " bytes" );
				return false;
			}
			checkPermissions();
			text = new String( Files.readAllBytes( path ), StandardCharsets.UTF_8 );
		} catch ( IOException e ) {
			problem( "can't be read, " + e.getMessage() );
			return false;
		}
		if ( text.equals( lastText ) ) return false;

		boolean newMaster;
		Map<String, Boolean> newRules = new LinkedHashMap<String, Boolean>();
		Map<String, Boolean> newEnabled = new LinkedHashMap<String, Boolean>();
		try {
			JsonNode root = new ObjectMapper( new YAMLFactory() ).readTree( text );
			if ( root == null || !root.isObject() ) throw new IllegalArgumentException( "must be a YAML mapping" );
			JsonNode v = root.get( "v" );
			if ( v != null && v.asInt() != 1 ) throw new IllegalArgumentException( "has unsupported version " + v );
			JsonNode e = root.get( "protect" );
			if ( e != null && !e.isBoolean() ) throw new IllegalArgumentException( "protect must be true or false" );
			newMaster = e == null || e.asBoolean();
			JsonNode r = root.get( "rules" );
			if ( r != null ) {
				if ( !r.isObject() ) throw new IllegalArgumentException( "rules must be an object" );
				java.util.Iterator<Map.Entry<String, JsonNode>> it = r.fields();
				while ( it.hasNext() ) {
					Map.Entry<String, JsonNode> entry = it.next();
					if ( !entry.getValue().isBoolean() ) {
						throw new IllegalArgumentException( "rule " + entry.getKey() + " must be true or false" );
					}
					newRules.put( entry.getKey(), entry.getValue().asBoolean() );
				}
			}
			JsonNode all = root.get( "sensors" );
			if ( all != null ) {
				if ( !all.isObject() ) throw new IllegalArgumentException( "sensors must be an object" );
				java.util.Iterator<Map.Entry<String, JsonNode>> it = all.fields();
				while ( it.hasNext() ) {
					Map.Entry<String, JsonNode> entry = it.next();
					String name = entry.getKey();
					if ( !entry.getValue().isObject() ) {
						throw new IllegalArgumentException( "sensor " + name + " must be an object with enabled or protect" );
					}
					java.util.Iterator<Map.Entry<String, JsonNode>> settings = entry.getValue().fields();
					while ( settings.hasNext() ) {
						Map.Entry<String, JsonNode> setting = settings.next();
						if ( !setting.getValue().isBoolean() ) {
							throw new IllegalArgumentException( name + " " + setting.getKey() + " must be true or false" );
						}
						if ( setting.getKey().equals( "enabled" ) ) newEnabled.put( name, setting.getValue().asBoolean() );
						else if ( setting.getKey().equals( "protect" ) ) newRules.put( name, setting.getValue().asBoolean() );
						else throw new IllegalArgumentException( "sensor " + name + " has an unknown setting " + setting.getKey() );
					}
				}
			}
		} catch ( IOException | IllegalArgumentException e ) {
			lastText = text;      // don't complain again about the same content
			problem( "is not valid, keeping the last settings, " + e.getMessage() );
			return false;
		}

		lastText = text;
		lastProblem = null;
		Map<String, Boolean> before = rules;
		Map<String, Boolean> beforeEnabled = enabled;
		boolean beforeMaster = master;
		master = newMaster;
		rules = newRules;
		enabled = newEnabled;
		Sensor.applyControl( master, rules, enabled );
		publishChanges( beforeMaster, before, beforeEnabled );
		return true;
	}

	private void publishChanges(boolean beforeMaster, Map<String, Boolean> before, Map<String, Boolean> beforeEnabled) {
		if ( beforeMaster != master ) {
			publish( "protect=" + ( master ? "on" : "off" ) );
		}
		for ( Map.Entry<String, Boolean> e : rules.entrySet() ) {
			if ( !e.getValue().equals( before.get( e.getKey() ) ) ) {
				publish( e.getKey() + "=" + ( e.getValue() ? "block" : "monitor" ) );
			}
		}
		Set<String> back = new java.util.LinkedHashSet<String>();
		for ( String name : before.keySet() ) {
			if ( !rules.containsKey( name ) ) back.add( name );
		}
		for ( Map.Entry<String, Boolean> e : enabled.entrySet() ) {
			if ( !e.getValue().equals( beforeEnabled.get( e.getKey() ) ) ) {
				publish( e.getKey() + "=" + ( e.getValue() ? "enabled" : "disabled" ) );
			}
		}
		for ( String name : beforeEnabled.keySet() ) {
			if ( !enabled.containsKey( name ) ) back.add( name );
		}
		for ( String name : back ) publish( name + "=default" );
	}

	private void publish(String change) {
		EventBus.publish( new Event( SENSOR, change, null, Event.Action.OBSERVED, "control file " + path ) );
	}

	private void problem(String text) {
		String message = "[JOT] control file " + path + " " + text;
		if ( !message.equals( lastProblem ) ) {
			lastProblem = message;
			System.err.println( message );
		}
	}

	/** Anyone who can write this file can switch protection off, so say if others can. */
	private void checkPermissions() throws IOException {
		if ( warnedPermissions ) return;
		try {
			Set<PosixFilePermission> perms = Files.getPosixFilePermissions( path );
			if ( perms.contains( PosixFilePermission.OTHERS_WRITE ) || perms.contains( PosixFilePermission.GROUP_WRITE ) ) {
				warnedPermissions = true;
				System.err.println( "[JOT] control file " + path + " can be written by other users. Anyone who can write it can switch "
						+ "protection off. Run chmod go-w on it." );
			}
		} catch ( UnsupportedOperationException e ) {
			// not a POSIX file system
		}
	}

}
