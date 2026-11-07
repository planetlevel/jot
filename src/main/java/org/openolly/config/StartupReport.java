package org.openolly.config;

import org.openolly.PlatformWork;
import org.openolly.Sensor;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;

/**
 * Says what this agent started with, as events from the sensor "jot-config", so the dashboard can show what is
 * really running and not what it guesses from files.
 *
 *   lock=monitor | lock=none    -Djot.protect=false locks every rule to report only, and the control file can't undo it
 *   jots=PATH                   the jots file the agent was started with
 *   reload=on | reload=off      whether the agent follows its files while the application runs, see SensorReloader
 *   ignore=default | ignore=[..] the ignore list it started with, which is read once, so a change to it needs a restart
 *   control=PATH | control=none the control file the agent polls
 *   loaded=NAME                 one for each sensor or rule that was loaded
 *   problem=FILE NAME TEXT      one for each mistake in a .jot file, which left a sensor or rule out
 *
 * A reload of the files while the application runs says loaded=NAME for a sensor that was added or replaced, and
 * unloaded=NAME for one that was removed, see SensorReloader.
 */
public final class StartupReport {

	static final String SENSOR = "jot-config";

	private StartupReport() {}

	public static void publish( String jotsFile ) {
		say( "lock=" + ( Sensor.isLockedToMonitor() ? "monitor" : "none" ) );
		say( "jots=" + jotsFile );
		say( "reload=" + ( SensorReloader.enabled() ? "on" : "off" ) );
		say( "ignore=" + ignore() );
		String control = System.getProperty( "jot.control" );
		say( "control=" + ( control == null || control.trim().isEmpty() ? "none" : control.trim() ) );
		for ( Sensor s : Sensor.getSensors() ) {
			if ( s.getName() != null ) say( "loaded=" + s.getName() );
		}
		for ( String problem : ConfigReader.getProblems() ) say( "problem=" + problem );
	}

	/** The ignore list the agent started with, which is read once. "default" when the jots file gave none, else the list as JSON. */
	static String ignore() {
		if ( PlatformWork.isDefault() ) return "default";
		try {
			return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString( PlatformWork.ignored() );
		} catch ( com.fasterxml.jackson.core.JsonProcessingException e ) {
			return "default";
		}
	}

	private static void say( String what ) {
		EventBus.publish( new Event( SENSOR, what, null, Event.Action.OBSERVED, "startup" ) );
	}
}
